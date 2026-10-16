"""Switch Updates: a section on the Games page with three tools over the plugin's library."""
from pokeldn.plugins import Field, Game, Tool

GROUP = ("On the console: HOME, highlight the game, press +, then Software Update, Match Version With Local Users, "
         "Next and Create Group.",
         "Leave the console on the group's screen, near the board, and press Start here.",
         "Choose what to do in the pop-up; when it says so, start matching the version on the console.")
IMPORTS = ("nsp", "nca", "zip", "7z", "rar", "tar", "gz", "tgz", "bz2", "tbz", "tbz2", "xz", "txz", "zst", "tzst")


def register(api):
    api.add_game(Game("switch", "Switch Updates", "Switch", "", (
        Tool("lcs-match", "Match Version", "lcs_match.py",
             "Back up the console's game update or system update, or send it a newer update from the library.",
             GROUP,
             fields=(Field("--system-version", "System version pokeldn claims",
                           help="major.minor.micro. Empty: the last one a console sent, else 20.5.0. It must be at "
                                "least the update's required system version.", hidden=True),),
             fixed=("--keys", "{keys}")),
        Tool("lcs-check", "Check saved updates", "lcs_check.py",
             "Hash every update in the library and verify Nintendo's signatures.",
             ("Nothing to do on the console.",),
             fields=(Field("--again", "Check files that passed before", kind="switch", hidden=True),),
             fixed=("--keys", "{keys}")),
        Tool("lcs-import", "Import an update", "lcs_import.py",
             "Add an NSP, or a system update's NCAs or archive, to the library once it checks.",
             ("Nothing to do on the console.",),
             fields=(Field("--file", "Update or system update", kind="file", exts=IMPORTS, required=True),),
             fixed=("--keys", "{keys}")),
    )), icon="switch.png")          # 18 x 18, as the built-in games' sprites (tools/make_icons.py)
