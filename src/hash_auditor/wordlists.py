"""Embedded wordlists and wordlist streaming for hash-auditor.

This module ships a genuine embedded wordlist corpus (~1,100 entries) built
from three literal text blocks:

* common passwords (top breach-list offenders),
* common English words,
* common given names and surnames.

At import time each block is zlib-compressed and base64-encoded into
'EMBEDDED_DATA', then decoded back into the public lists. The round-trip
keeps the source readable while exercising the same compressed-blob code path
used for external wordlists.

Public API
----------
EMBEDDED_PASSWORDS
    list[str] -- the embedded common-password list.
EMBEDDED_WORDS
    list[str] -- common English words plus names (cracking fodder).
EMBEDDED_NAMES
    list[str] -- the embedded name list.
EMBEDDED_DATA
    dict[str, str] -- zlib/base64 blobs keyed by section name.
load_wordlist(path)
    generator yielding cleaned words from a file, with encoding detection.
stream_candidates(paths)
    generator chaining several wordlist files, de-duplicated.

Pure standard library. Deterministic. No network access.
"""

from __future__ import annotations

import base64
import codecs
import zlib
from pathlib import Path
from typing import Iterable, Iterator

__all__ = [
    "EMBEDDED_PASSWORDS",
    "EMBEDDED_WORDS",
    "EMBEDDED_NAMES",
    "EMBEDDED_DATA",
    "load_wordlist",
    "stream_candidates",
]

# ---------------------------------------------------------------------------
# Literal source blocks. Each block is whitespace-separated; order encodes
# rough popularity (most common first), which downstream rankers exploit.
# ---------------------------------------------------------------------------

_PASSWORD_BLOCK = """
password 123456 123456789 12345678 12345 1234567 1234567890 qwerty abc123 password1
iloveyou admin welcome monkey login letmein dragon master sunshine princess
starwars shadow superman batman trustno1 freedom whatever qazwsx 654321 666666
696969 111111 000000 121212 112233 123123 1q2w3e4r q1w2e3r4 zaq12wsx 1qaz2wsx
qwerty123 qwertyuiop 123qwe zxcvbnm asdfghjkl asdfgh zxcvbn 123abc letmein1 hello123
charlie donald loveme football baseball soccer hockey michael jennifer jordan
harley ranger hunter thomas robert daniel maggie shakeit babygirl snowball
secret ginger summer ashley mustang bond007 coolman cowboy denise dolphins
eagle falcon ferrari firebird gemini goddess heaven ironman jasmine knight
ladybug loveyou matrix merlin ncc1701 ninja panther peaches peanut phoenix
player qwer1234 rabbit rocket silver skippy slayer snoopy sparky spider
tiger turtles unicorn victoria viking warrior wizard xavier yellow zebra
zombie computer internet pepper magic cookie orange purple banana flower
horse tigger roxy killer cheese testing coconut coffee dallas yankees
thunder taylor alexis lindsay willow corvette 1234qwer 987654321 7777777 123321 555555
112358 password123 passw0rd p@ssw0rd admin123 root toor changeme default letmein123
welcome1 qwerty1 iloveu 123456a a123456 5201314 woaini w123456 abc123456 aa123456
a123456789 00000000 88888888 147258369 159357 741852963 963852741 159753 asd123 admin1
12341234 11111111 12344321 pass123 test123 user guest demo sample temp
temporary password! Pa55word Pass123 Admin@123 Welcome123 Qwerty123 P@ssw0rd! iloveyou1 babyboy
cutie princess1 angel angels love123 sexy123 red123 white123 black123 green123
blue123 money1 cash dollar eagle1 falcon1 rocket1 silver1 golden diamond
platinum crystal blazer racing runner sprinter champion legend hero captain chief
boss king queen prince duke baron royal ace joker poker
casino vegas lucky7 winner loser gamer gaming player1 sniper ghost
phantom dark light storm lightning tornado hurricane volcano earthquake tsunami
apple amazon google facebook twitter linkedin instagram tiktok youtube netflix
spotify minecraft fortnite roblox pokemon pikachu mario luigi sonic zelda
halo warcraft starcraft overwatch counterstrike samsung huawei xiaomi nokia motorola
lenovo asus acer sony iphone android windows linux ubuntu
debian fedora archlinux freebsd openbsd solaris python java javascript typescript
ruby golang rustlang kotlin swift mysql postgres sqlite mongodb
redis oracle docker kubernetes ansible terraform security hacker cracking cipher
crypto blockchain bitcoin ethereum wallet satoshi mining
"""

_WORD_BLOCK_A = """
time year people way day man thing woman life child
world school state family student group country problem hand part
place case week company system program question work government number
night point home water room mother area money story fact
month lot right study book eye job word business issue
side kind head house service friend father power hour game
line end member law car city community name president team
minute idea body information back parent face level office door
person art war health history party result change morning reason
research girl guy moment air teacher force education foot boy
age policy process music market sense nation plan college interest
death experience effect use class control care field development role
effort rate heart drug show leader light voice wife police
mind price report shoulder army husband bank media village farm
building battle claim earth knowledge river island mountain forest weather
ocean desert valley bridge road street garden flower tree grass
leaf root seed fruit vegetable bread meat milk butter sugar
salt pepper coffee tea juice wine beer soda breakfast lunch
dinner meal snack dessert cake candy chocolate spoon fork knife
plate bowl glass cup bottle pan pot oven stove fridge
freezer sink towel soap shampoo brush comb mirror clock lamp
chair table desk bed sofa couch carpet curtain window wall
floor ceiling roof stairs elevator garage yard fence gate path
trail map compass tent camp fire smoke ash dust sand
rock stone metal gold iron steel copper bronze wood paper
pencil pen ink paint color red blue green yellow black
white gray brown pink purple orange silver north south east
west left right up down over under again further then
once here there when where why how all any both
each few more most other some such only own same
than too very can will just should now between high
low old new young long short great small large big
next last first like round open close begin finish keep
let make put run move live believe bring happen write
provide sit stand lose pay meet include continue set learn
lead understand watch follow stop create speak read allow add
spend grow walk win offer remember love consider appear buy
wait serve die send expect build stay fall cut reach
kill remain suggest raise pass sell require decide pull
"""

_WORD_BLOCK_B = """
morning evening afternoon tonight yesterday tomorrow today week month year
spring summer autumn winter january february march april may june
july august september october november december monday tuesday wednesday thursday
friday saturday sunday apple banana cherry grape lemon mango melon
peach pear plum berry kiwi coconut pineapple tomato potato carrot
onion garlic corn wheat rice oat bean pea lettuce cucumber
pepper mushroom pumpkin walnut almond cashew pecan hazelnut peanut butter
cheese yogurt cream egg bacon ham beef pork chicken turkey
lamb fish salmon tuna shrimp crab lobster snail frog snake
lizard turtle rabbit hamster guinea parrot pigeon sparrow crow eagle
hawk owl falcon robin wren finch canary swan duck goose
penguin ostrich emu kiwi dodo whale dolphin shark seal walrus
otter beaver badger fox wolf bear lion leopard cheetah jaguar
panther tiger gorilla chimpanzee monkey baboon lemur sloth koala panda
kangaroo wallaby wombat platypus echidna armadillo anteater hedgehog porcupine squirrel
chipmunk mouse rat mole shrew bat horse donkey mule zebra
camel llama alpaca goat sheep cow bull ox elk
deer moose antelope bison buffalo rhino hippo elephant giraffe
castle palace tower fortress temple church mosque shrine monastery cathedral
cottage cabin hut tent igloo mansion villa bungalow apartment studio
loft duplex townhouse farmhouse ranch barn stable coop kennel hutch
garden orchard meadow pasture prairie savanna jungle rainforest swamp marsh
bog pond lake creek stream river waterfall geyser spring well
oasis canyon gorge cliff bluff dune beach shore coast harbor
bay gulf cove lagoon reef atoll volcano crater summit ridge
peak hill mound knoll plateau plain valley basin delta
estuary strait isthmus peninsula cape island archipelago continent ocean sea
"""

_NAME_BLOCK = """
james john robert william david richard joseph charles christopher daniel
matthew anthony mark donald steven paul andrew joshua kenneth kevin
brian george timothy ronald edward jason jeffrey ryan jacob gary
nicholas eric jonathan stephen larry justin scott brandon benjamin samuel
raymond gregory frank alexander patrick jack dennis jerry tyler aaron
jose nathan henry carl douglas peter arthur gerald roger keith
jeremy terry lawrence sean christian albert joe ethan willie jesse
ralph billy bruce bryan mary patricia linda barbara elizabeth susan
jessica sarah karen lisa nancy betty margaret sandra kimberly emily
donna michelle carol amanda melissa deborah stephanie dorothy rebecca sharon
laura cynthia kathleen amy angela shirley anna brenda pamela nicole
samantha katherine christine helen debra rachel carolyn janet catherine maria
heather diane ruth julie olivia joyce virginia victoria kelly madison
lauren crystal rose smith johnson williams brown jones garcia miller
davis rodriguez martinez hernandez lopez gonzalez wilson anderson taylor moore
jackson martin lee perez thompson harris sanchez clark ramirez lewis
robinson walker young allen king wright torres nguyen hill flores
green adams nelson baker hall rivera campbell mitchell carter roberts
gomez phillips evans turner diaz parker cruz edwards collins reyes
stewart morris morales murphy cook rogers gutierrez ortiz morgan cooper
peterson bailey reed kelly howard ramos kim cox ward watson
brooks chavez wood bennett gray mendoza ruiz hughes price
"""

# ---------------------------------------------------------------------------
# Compression round-trip: literal blocks -> zlib/base64 blobs -> word lists.
# ---------------------------------------------------------------------------


def _pack(text: str) -> str:
    """Compress a text block to a base64-encoded zlib blob."""
    return base64.b64encode(zlib.compress(text.encode("utf-8"), 9)).decode("ascii")


def _unpack(blob: str) -> str:
    """Inverse of _pack()."""
    return zlib.decompress(base64.b64decode(blob.encode("ascii"))).decode("utf-8")


#: zlib/base64 blobs of the raw literal blocks, keyed by section name.
EMBEDDED_DATA: dict[str, str] = {
    "passwords": _pack(_PASSWORD_BLOCK),
    "words": _pack(_WORD_BLOCK_A + "\n" + _WORD_BLOCK_B),
    "names": _pack(_NAME_BLOCK),
}


def _split(blob: str) -> list[str]:
    """Decode a blob and return its whitespace tokens, de-duplicated in order."""
    seen: set[str] = set()
    out: list[str] = []
    for token in _unpack(blob).split():
        if token and token not in seen:
            seen.add(token)
            out.append(token)
    return out


#: Embedded common passwords, most popular first.
EMBEDDED_PASSWORDS: list[str] = _split(EMBEDDED_DATA["passwords"])

#: Embedded common names, most popular first.
EMBEDDED_NAMES: list[str] = _split(EMBEDDED_DATA["names"])

_word_tokens = _split(EMBEDDED_DATA["words"])
#: Common English words plus names -- the general cracking fodder list.
EMBEDDED_WORDS: list[str] = _word_tokens + [
    n for n in EMBEDDED_NAMES if n not in set(_word_tokens)
]
del _word_tokens


# ---------------------------------------------------------------------------
# External wordlist loading.
# ---------------------------------------------------------------------------


def _decode(raw: bytes) -> str:
    """Best-effort text decoding with BOM sniffing and fallback encodings.

    Tries, in order: UTF-16 BOM, UTF-8 BOM, strict UTF-8, then CP1252 with
    replacement (CP1252 covers legacy Windows wordlists and is a practical
    superset of printable Latin-1).
    """
    if raw.startswith(codecs.BOM_UTF16_LE) or raw.startswith(codecs.BOM_UTF16_BE):
        return raw.decode("utf-16")
    if raw.startswith(codecs.BOM_UTF8):
        return raw.decode("utf-8-sig")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def load_wordlist(path: str | Path) -> Iterator[str]:
    """Yield cleaned candidate words from a wordlist file.

    Behaviour:

    * Encoding is detected (UTF-8 / UTF-8 BOM / UTF-16 / CP1252 fallback).
    * Lines are stripped; blank lines and '#' comment lines are skipped.
    * Words are yielded in file order; de-duplication is the caller's job
      (see stream_candidates()).

    Raises FileNotFoundError if the path does not exist.
    """
    p = Path(path)
    raw = p.read_bytes()
    for line in _decode(raw).splitlines():
        word = line.strip()
        if not word or word.startswith("#"):
            continue
        yield word


def stream_candidates(paths: Iterable[str | Path]) -> Iterator[str]:
    """Chain several wordlist files into one de-duplicated candidate stream.

    Files are read lazily in the given order; a word is yielded only on its
    first occurrence across all files. Missing files raise FileNotFoundError
    from the underlying load_wordlist().
    """
    seen: set[str] = set()
    for path in paths:
        for word in load_wordlist(path):
            if word not in seen:
                seen.add(word)
                yield word
