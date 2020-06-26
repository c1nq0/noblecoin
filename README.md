
# NobleCoin [NOBL] #

Noblecoin is a Hybrid-based cryptocurrency. Pos VII and POW M7M 

### Version 2.1.1.0: Client Update - LevelDB + Fast Start-up
Switch from Berkeley database to google LevelDB (1 file version)
Integrated fast start-up
Client update to work with boost 1.66

Version 2.1.1.0 is fully compatible with v2.1.0.0. Update is not necesssary.

Because of switch to levelDB and fast-startup, the local database needs to recreated, 
either from bootstrap or ReSync.


### Version 2.1.0.0: Fork @ Height 1610644
Fork to transition to permanent hybrid wallet with POS V2 and POW (M7M) 
A reload of the blockchain is not necessary.
POW reward has been set at 5 NOBL.
Protocol version increased to 90000. Lower versions are disabled.


### Version < 2.1.0.0:
are no longer compatible. They will not accept the new POW blocks.
Upgrade to at least version 2.1.0.0 is mandatory.






Development process
===========================

Developers work in their own trees, then submit pull requests when
they think their feature or bug fix is ready.

The patch will be accepted if there is broad consensus that it is a
good thing.  Developers should expect to rework and resubmit patches
if they don't match the project's coding conventions (see coding.txt)
or are controversial.

The master branch is regularly built and tested, but is not guaranteed
to be completely stable. Tags are regularly created to indicate new
stable release versions of Noblecoin.

Feature branches are created when there are major new features being
worked on by several people.

From time to time a pull request will become outdated. If this occurs, and
the pull is no longer automatically mergeable; a comment on the pull will
be used to issue a warning of closure. The pull will be closed 15 days
after the warning if action is not taken by the author. Pull requests closed
in this manner will have their corresponding issue labeled 'stagnant'.

Issues with no commits will be given a similar warning, and closed after
15 days from their last activity. Issues closed in this manner will be 
labeled 'stale'.
