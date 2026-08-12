#!/usr/bin/perl

# The session must be released however the caller leaves.
#
# Twenty of the plugin's methods build an API object and nine of them have a
# `die` between the construction and the `logout`. Each of those leaked a DSM
# session, and R-13 established that a second login does not evict the first —
# so they accumulate on the NAS. DESTROY closes all nine at once.
#
# The tests below are about the ways a DESTROY like this goes wrong, not about
# whether it logs out on the happy path.
#
# One of them had to be corrected after it was written, and the correction is
# recorded above the subtest itself: it claimed to prove that `local $@` was
# needed on the die path, and it passed with `local $@` removed. Perl handles
# that path. The hazard `local $@` really covers is ordinary scope exit while the
# caller is still holding an error — and only after being rewritten did the test
# fail on that regression.

use strict;
use warnings;
use Test::More;
use POSIX ();
use lib 'lib';

require_ok('PVE::Storage::Custom::Synology::API');
my $CLASS = 'PVE::Storage::Custom::Synology::API';

# A logout that never touches the network. It records the call and, crucially,
# performs an internal eval that fails — because a real logout can fail, and a
# DESTROY without `local $@` would then leave that failure in $@.
our @LOGGED_OUT;
{
    no warnings 'redefine', 'once';
    *PVE::Storage::Custom::Synology::API::logout = sub {
        my ($self) = @_;
        return if !defined $self->{sid};
        push @LOGGED_OUT, $self->{sid};
        eval { die "the NAS refused the logout\n" };   # a plausible real failure
        $self->{sid} = undef;
        return;
    };
}

sub make_api {
    my (%o) = @_;
    my $api = $CLASS->new(portals => '192.0.2.1', storeid => 't', %o);
    $api->{sid} = $o{sid} // 'session-abc';
    return $api;
}

subtest 'an object going out of scope releases its session' => sub {
    local @LOGGED_OUT = ();
    { my $api = make_api(sid => 'plain-scope-exit'); }
    is_deeply(\@LOGGED_OUT, ['plain-scope-exit'], 'logged out on scope exit');
};

subtest 'a die between construction and logout still releases it' => sub {
    local @LOGGED_OUT = ();
    eval {
        my $api = make_api(sid => 'died-before-logout');
        die "a rollback the NAS refused\n";
    };
    is_deeply(\@LOGGED_OUT, ['died-before-logout'],
              'the session is released on the die path — the nine leaks');
};

# THE ONE THAT NEEDED CORRECTING.
#
# The first version of this subtest claimed to prove that `local $@` was
# necessary by dying past the destructor — and it PASSED with `local $@` removed.
# Perl 5.14 and later save and restore `$@` around destructor calls made while a
# `die` is propagating, so that path was never at risk and the test was measuring
# nothing. A guard that cannot fail is a guard that lies about its coverage.
#
# The reachable hazard is ordinary scope exit while the caller is holding a `$@`
# it has not finished with. The plugin is full of `eval { ... }; if ($@) { ... }`,
# and an API object falling out of scope in between would replace the error with
# whatever the logout did. Perl does not protect that.
subtest '$@ survives an object going out of scope' => sub {
    local @LOGGED_OUT = ();

    eval { die "the NAS refused the resize\n" };
    is($@, "the NAS refused the resize\n", 'the caller has an error in hand');

    { my $api = make_api(sid => 'scope-exit-mid-error'); }

    is($@, "the NAS refused the resize\n",
       'and still has it after the destructor ran');
    unlike($@, qr/refused the logout/,
           'not the failure from inside the logout');
    is_deeply(\@LOGGED_OUT, ['scope-exit-mid-error'], 'which did happen');
};

# And the die path, which Perl handles itself. Kept because it is what the nine
# leaking methods actually do, even though `local $@` is not what saves it.
subtest 'a session is released even when the caller dies past the logout' => sub {
    local @LOGGED_OUT = ();
    eval {
        my $api = make_api(sid => 'died-past-logout');
        die "a rollback the NAS refused\n";
    };
    is($@, "a rollback the NAS refused\n", 'the error propagates intact');
    is_deeply(\@LOGGED_OUT, ['died-past-logout'], 'and the session is released');
};

# A forked child must not log out the parent's session. PVE forks workers, and
# a child cleaning up on exit would invalidate a session the parent is still
# using — which reads as the NAS dropping sessions at random.
subtest 'a forked child does not release the parent session' => sub {
    my $tmp = "/tmp/jt-syno-session-test.$$";
    unlink $tmp;

    {
        no warnings 'redefine';
        local *PVE::Storage::Custom::Synology::API::logout = sub {
            my ($self) = @_;
            return if !defined $self->{sid};
            open(my $fh, '>>', $tmp) or return;
            print $fh "$$ logged out $self->{sid}\n";
            close($fh);
            $self->{sid} = undef;
            return;
        };

        my $api = make_api(sid => 'parent-session');

        my $pid = fork();
        BAIL_OUT('cannot fork') if !defined $pid;
        if ($pid == 0) {
            # The child holds a copy of $api. Exiting must not release it.
            POSIX::_exit(0);
        }
        waitpid($pid, 0);

        my $after_child = -e $tmp ? do { open(my $f,'<',$tmp); local $/; <$f> } : '';
        is($after_child, '', 'the child exited without touching the session');

        undef $api;   # now the parent lets it go
    }

    my $after_parent = -e $tmp ? do { open(my $f,'<',$tmp); local $/; <$f> } : '';
    like($after_parent, qr/^$$ logged out parent-session$/m,
         'and the parent released it itself');
    unlink $tmp;
};

subtest 'an object that never logged in does nothing' => sub {
    local @LOGGED_OUT = ();
    {
        my $api = $CLASS->new(portals => '192.0.2.1', storeid => 't');
        is($api->{sid}, undef, 'no session was ever established');
    }
    is_deeply(\@LOGGED_OUT, [], 'so there is nothing to release and nothing is tried');
};

subtest 'the guards are actually present in the source' => sub {
    open(my $fh, '<', 'lib/PVE/Storage/Custom/Synology/API.pm')
        or BAIL_OUT('cannot read API.pm');
    my $src = do { local $/; <$fh> };
    close($fh);

    my ($destroy) = $src =~ /\nsub DESTROY \{(.*?)\n\}/s;
    ok($destroy, 'DESTROY exists');
    like($destroy, qr/GLOBAL_PHASE/,
         'skips global destruction, when the HTTP client may already be gone');
    like($destroy, qr/owner_pid/,     'checks the pid, so a fork is not confused for a scope exit');
    like($destroy, qr/local \$\@/,    'localises $@ so it cannot eat the caller\'s error');
    like($destroy, qr/eval \{/,       'and cannot escape at all');
};

# --- the scope guard, which is what makes the credential cleanup unmissable ---
#
# on_delete_hook removed the storage's targets from the NAS and returned early
# when the NAS could not be reached — and that early return left the stored DSM
# credential on disk for a storage that no longer existed.
subtest 'Deferred runs on every exit path' => sub {
    require PVE::Storage::Custom::Synology::Deferred;
    my $D = 'PVE::Storage::Custom::Synology::Deferred';

    my @ran;

    # plain scope exit
    { my $g = $D->new(sub { push @ran, 'scope' }); }
    is_deeply(\@ran, ['scope'], 'on scope exit');

    # an early return, which is the case that was lost
    @ran = ();
    my $early = sub {
        my $g = $D->new(sub { push @ran, 'early-return' });
        return 'gave up';
    };
    is($early->(), 'gave up', 'the sub returned early');
    is_deeply(\@ran, ['early-return'], 'and the cleanup still ran');

    # a die
    @ran = ();
    eval {
        my $g = $D->new(sub { push @ran, 'died' });
        die "the NAS did not answer\n";
    };
    is($@, "the NAS did not answer\n", 'the error propagates');
    is_deeply(\@ran, ['died'], 'and the cleanup ran anyway');

    # cancel, for the caller that no longer wants it
    @ran = ();
    { my $g = $D->new(sub { push @ran, 'cancelled' }); $g->cancel; }
    is_deeply(\@ran, [], 'cancel means it does not run');

    # a failing cleanup must not become the caller's error
    @ran = ();
    my $warned = '';
    eval {
        local $SIG{__WARN__} = sub { $warned .= $_[0] };
        my $g = $D->new(sub { die "cleanup itself failed\n" });
        die "the real error\n";
    };
    is($@, "the real error\n", 'a failing cleanup does not replace the real error');
    like($warned, qr/deferred cleanup failed/, 'it is reported as a warning instead');

    eval { $D->new('not a coderef') };
    like($@, qr/needs a code reference/, 'and it refuses anything but a coderef');
};

# ---------------------------------------------------------------------------
# A worker never reaches global destruction, so nothing may hold the client past
# the method that made it.
#
# From the related dellemc project, which met this on a customer's array:
# `PVE::RESTEnvironment::fork_worker` ends the child with `POSIX::_exit`, which
# skips END blocks, global destruction, and even the flushing of buffered output.
# A worker is what runs `qm create`, `qm destroy` and every other task that
# touches a volume — so a session released "at exit" is a session never released.
#
# This plugin is safe for one reason only: `_api` returns a NEW object every call
# and nothing keeps it, so the client is freed when the plugin method returns and
# DESTROY runs there, long before any `_exit`. That is a property worth asserting
# rather than trusting, because a per-process client cache is exactly the kind of
# optimisation someone adds later — it is what dellemc had, and it is what turned
# `_exit` into a leak there.
#
# The `${^GLOBAL_PHASE} eq 'DESTRUCT'` guard in DESTROY is therefore belt and
# braces on this path, not the thing that saves it.
subtest 'nothing keeps the client past the call that made it' => sub {
    my $src = do {
        open(my $fh, '<', 'lib/PVE/Storage/Custom/SynologySANPlugin.pm')
            or plan skip_all => 'plugin source not readable';
        local $/; <$fh>;
    };

    # Comments and heredocs would otherwise let a mention of a cache read as one.
    $src =~ s/^\s*#.*$//mg;

    unlike($src, qr/\bour \s* \$ \w* (?:api|client|session) \w*/xi,
        'no package variable holds an API client');
    unlike($src, qr/\$cache -> \{ [^}]* \} \s* (?:\/\/)?= \s* [^;]* _api/xs,
        "PVE's own \$cache is not used to keep one either");

    # And the constructor really does hand out a fresh object each time.
    my @made;
    no warnings 'redefine';
    local *PVE::Storage::Custom::Synology::API::new = sub {
        my $o = bless { owner_pid => $$ }, $CLASS;
        push @made, $o;
        return $o;
    };
    my $a = PVE::Storage::Custom::Synology::API->new;
    my $b = PVE::Storage::Custom::Synology::API->new;
    isnt("$a", "$b", 'two calls are two objects, so neither outlives its caller');
};

done_testing();
