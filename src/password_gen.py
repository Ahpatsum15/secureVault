"""
Secure password and passphrase generation module.

Uses cryptographically secure random number generation (secrets module)
to generate strong passwords and passphrases.
"""

import secrets
import string
import math
from typing import List


# Default character sets
LOWERCASE = string.ascii_lowercase
UPPERCASE = string.ascii_uppercase
DIGITS = string.digits
SPECIAL = "!@#$%^&*()_+-=[]{}|;:,.<>?"


def generate_password(
    length: int = 20,
    use_lowercase: bool = True,
    use_uppercase: bool = True,
    use_digits: bool = True,
    use_special: bool = True
) -> str:
    """
    Generate a cryptographically secure random password.
    
    Args:
        length: Length of the password (default: 20)
        use_lowercase: Include lowercase letters (default: True)
        use_uppercase: Include uppercase letters (default: True)
        use_digits: Include digits (default: True)
        use_special: Include special characters (default: True)
        
    Returns:
        Generated password string
        
    Raises:
        ValueError: If length < 1 or no character sets selected
    """
    if length < 1:
        raise ValueError("Password length must be at least 1")
    
    # Build character set
    charset = ""
    if use_lowercase:
        charset += LOWERCASE
    if use_uppercase:
        charset += UPPERCASE
    if use_digits:
        charset += DIGITS
    if use_special:
        charset += SPECIAL
    
    if not charset:
        raise ValueError("At least one character set must be selected")
    
    # Generate password using secrets.choice for cryptographic security
    password = ''.join(secrets.choice(charset) for _ in range(length))
    
    return password


def generate_passphrase(
    num_words: int = 6,
    separator: str = "-",
    word_list: List[str] = None
) -> str:
    """
    Generate a cryptographically secure passphrase using random words.
    
    Uses a built-in word list if none provided. For maximum security,
    consider using the EFF's long wordlist (7776 words).
    
    Args:
        num_words: Number of words in the passphrase (default: 6)
        separator: Character(s) to separate words (default: "-")
        word_list: Custom word list (default: built-in list)
        
    Returns:
        Generated passphrase string
        
    Raises:
        ValueError: If num_words < 1
    """
    if num_words < 1:
        raise ValueError("Number of words must be at least 1")
    
    # Use default word list if none provided
    if word_list is None:
        word_list = _get_default_wordlist()
    
    if not word_list:
        raise ValueError("Word list cannot be empty")
    
    # Generate passphrase using secrets.choice
    words = [secrets.choice(word_list) for _ in range(num_words)]
    
    return separator.join(words)


def calculate_entropy(password: str, charset_size: int = None) -> float:
    """
    Calculate the entropy of a password in bits.
    
    Entropy = log2(charset_size ^ length)
    
    Args:
        password: The password to analyze
        charset_size: Size of character set (auto-detected if None)
        
    Returns:
        Entropy in bits
    """
    if not password:
        return 0.0
    
    # Auto-detect charset size if not provided
    if charset_size is None:
        charset_size = _detect_charset_size(password)
    
    # Calculate entropy: log2(charset_size^length)
    entropy = len(password) * math.log2(charset_size)
    
    return entropy


def _detect_charset_size(password: str) -> int:
    """
    Detect the character set size based on characters present in password.
    
    Args:
        password: The password to analyze
        
    Returns:
        Estimated character set size
    """
    has_lowercase = any(c in LOWERCASE for c in password)
    has_uppercase = any(c in UPPERCASE for c in password)
    has_digits = any(c in DIGITS for c in password)
    has_special = any(c in SPECIAL for c in password)
    
    charset_size = 0
    if has_lowercase:
        charset_size += len(LOWERCASE)
    if has_uppercase:
        charset_size += len(UPPERCASE)
    if has_digits:
        charset_size += len(DIGITS)
    if has_special:
        charset_size += len(SPECIAL)
    
    # If no recognized characters, assume at least the unique characters present
    if charset_size == 0:
        charset_size = len(set(password))
    
    return charset_size


def _get_default_wordlist() -> List[str]:
    """
    Get a default word list for passphrase generation.
    
    This is a curated list of common, easy-to-type words.
    For production use, consider using the EFF's long wordlist.
    
    Returns:
        List of words
    """
    return [
        "able", "about", "account", "acid", "across", "action", "addition", "adjust",
        "adult", "after", "again", "against", "agree", "almost", "already", "also",
        "amount", "angle", "angry", "animal", "answer", "apple", "approve", "argue",
        "army", "around", "arrive", "artist", "attack", "attempt", "autumn", "avoid",
        "awake", "baby", "back", "balance", "ball", "band", "bank", "base",
        "basket", "battle", "beach", "beauty", "become", "before", "begin", "believe",
        "benefit", "best", "better", "between", "bird", "birth", "bitter", "black",
        "blade", "blood", "blow", "blue", "board", "boat", "body", "bone",
        "book", "border", "bottle", "bottom", "brain", "branch", "brave", "bread",
        "break", "breath", "bridge", "brief", "bright", "bring", "broad", "brother",
        "brown", "brush", "build", "burn", "burst", "business", "butter", "button",
        "camera", "canvas", "capital", "captain", "carbon", "careful", "carpet", "carry",
        "castle", "catch", "cause", "center", "certain", "chain", "chair", "chance",
        "change", "charge", "cheap", "cheese", "chemical", "chest", "chief", "child",
        "choice", "circle", "city", "claim", "class", "clean", "clear", "climb",
        "clock", "close", "cloth", "cloud", "coal", "coast", "coffee", "cold",
        "collect", "color", "column", "combine", "come", "comfort", "common", "company",
        "compare", "complete", "complex", "compute", "concept", "concern", "condition", "connect",
        "consider", "contain", "continue", "control", "copper", "copy", "corner", "correct",
        "cotton", "count", "country", "course", "cover", "crack", "crash", "cream",
        "create", "credit", "crime", "cross", "crowd", "crown", "cruel", "crush",
        "culture", "current", "curtain", "curve", "custom", "damage", "danger", "dark",
        "daughter", "debate", "decide", "deep", "defeat", "defend", "degree", "delay",
        "deliver", "demand", "depend", "describe", "desert", "design", "desire", "destroy",
        "detail", "develop", "device", "diamond", "differ", "difficult", "dinner", "direct",
        "discover", "discuss", "disease", "distance", "divide", "doctor", "dollar", "domain",
        "double", "doubt", "down", "dragon", "drama", "draw", "dream", "dress",
        "drink", "drive", "drop", "during", "dust", "early", "earth", "east",
        "easy", "edge", "educate", "effect", "effort", "either", "electric", "element",
        "elephant", "employ", "empty", "enable", "enemy", "energy", "engine", "enjoy",
        "enough", "enter", "entire", "equal", "escape", "even", "evening", "event",
        "every", "exact", "example", "except", "exchange", "exist", "expand", "expect",
        "expense", "expert", "explain", "express", "extend", "extra", "extreme", "face",
        "fact", "factor", "fail", "fair", "fall", "false", "family", "famous",
        "farm", "fashion", "fast", "father", "fault", "favor", "fear", "feature",
        "feel", "female", "fence", "field", "fight", "figure", "file", "fill",
        "final", "finance", "find", "finger", "finish", "fire", "first", "fish",
        "fixed", "flag", "flame", "flat", "flight", "float", "floor", "flower",
        "fluid", "focus", "follow", "food", "force", "forest", "forget", "form",
        "formal", "former", "forward", "found", "frame", "free", "fresh", "friend",
        "front", "fruit", "fuel", "full", "function", "future", "gain", "game",
        "garden", "general", "gentle", "gift", "girl", "give", "glass", "global",
        "gold", "good", "govern", "grain", "grand", "grass", "grave", "great",
        "green", "ground", "group", "grow", "guard", "guess", "guide", "guitar",
        "habit", "half", "hammer", "hand", "handle", "hang", "happen", "happy",
        "harbor", "hard", "harm", "harvest", "hate", "have", "head", "health",
        "hear", "heart", "heat", "heavy", "height", "help", "hidden", "high",
        "history", "hold", "hole", "holiday", "home", "honest", "honor", "hope",
        "horse", "hospital", "hotel", "hour", "house", "human", "hundred", "hunger",
        "hunt", "hurry", "husband", "idea", "image", "imagine", "impact", "import",
        "improve", "include", "income", "increase", "indeed", "industry", "infant", "inform",
        "initial", "injury", "insect", "inside", "instead", "interest", "invent", "invest",
        "invite", "involve", "iron", "island", "issue", "item", "jacket", "join",
        "joint", "journey", "judge", "jump", "junior", "just", "keep", "kettle",
        "king", "kitchen", "knee", "knife", "knock", "know", "label", "labor",
        "ladder", "lady", "lake", "lamp", "land", "language", "large", "last",
        "late", "laugh", "launch", "layer", "lead", "leader", "leaf", "learn",
        "least", "leather", "leave", "left", "legal", "lemon", "length", "less",
        "lesson", "letter", "level", "library", "license", "life", "lift", "light",
        "limit", "line", "link", "liquid", "list", "listen", "little", "live",
        "local", "lock", "logic", "long", "look", "loose", "lose", "loss",
        "love", "lower", "loyal", "lucky", "lunch", "machine", "magic", "main",
        "major", "make", "male", "manage", "manner", "many", "marble", "march",
        "margin", "mark", "market", "marry", "master", "match", "material", "matter",
        "maybe", "meal", "mean", "measure", "meat", "media", "medical", "medium",
        "meet", "member", "memory", "mental", "mention", "merchant", "message", "metal",
        "method", "middle", "might", "military", "milk", "million", "mind", "mine",
        "minister", "minor", "minute", "mirror", "miss", "mistake", "mixed", "model",
        "modern", "moment", "money", "month", "moon", "moral", "more", "morning",
        "most", "mother", "motion", "motor", "mountain", "mouse", "mouth", "move",
        "much", "muscle", "music", "must", "mutual", "myself", "mystery", "name",
        "narrow", "nation", "native", "natural", "nature", "near", "necessary", "neck",
        "need", "negative", "neighbor", "neither", "nerve", "network", "never", "news",
        "next", "nice", "night", "noble", "noise", "none", "normal", "north",
        "nose", "note", "nothing", "notice", "novel", "number", "nurse", "object",
        "observe", "obtain", "obvious", "occasion", "occupy", "occur", "ocean", "offer",
        "office", "officer", "official", "often", "operate", "opinion", "oppose", "opposite",
        "option", "orange", "order", "ordinary", "organ", "organize", "origin", "original",
        "other", "ought", "outcome", "outdoor", "outer", "output", "outside", "over",
        "owner", "package", "page", "pain", "paint", "pair", "palace", "panel",
        "paper", "parent", "park", "part", "particle", "particular", "partly", "partner",
        "party", "pass", "passage", "past", "path", "patient", "pattern", "pause",
        "payment", "peace", "peak", "people", "pepper", "percent", "perfect", "perform",
        "perhaps", "period", "permit", "person", "phase", "phone", "photo", "phrase",
        "physical", "piano", "pick", "picture", "piece", "pilot", "pink", "pipe",
        "place", "plain", "plan", "plane", "planet", "plant", "plastic", "plate",
        "platform", "play", "please", "pleasure", "plenty", "plot", "pocket", "poem",
        "point", "poison", "pole", "police", "policy", "polish", "polite", "political",
        "pool", "poor", "popular", "population", "port", "position", "positive", "possible",
        "post", "potato", "pound", "powder", "power", "practice", "praise", "predict",
        "prefer", "prepare", "present", "preserve", "press", "pressure", "pretend", "pretty",
        "prevent", "previous", "price", "pride", "primary", "prince", "print", "prior",
        "prison", "private", "prize", "problem", "process", "produce", "product", "profit",
        "program", "progress", "project", "promise", "promote", "proof", "proper", "property",
        "propose", "protect", "protest", "proud", "prove", "provide", "public", "pull",
        "pump", "punish", "pupil", "purchase", "pure", "purple", "purpose", "push",
        "quality", "quarter", "queen", "question", "quick", "quiet", "quite", "quote",
        "race", "radio", "rail", "rain", "raise", "range", "rank", "rapid",
        "rare", "rate", "rather", "reach", "react", "read", "ready", "real",
        "reason", "recall", "receive", "recent", "recipe", "record", "reduce", "refer",
        "reflect", "refuse", "regard", "region", "regret", "regular", "reject", "relate",
        "release", "relevant", "relief", "religion", "rely", "remain", "remark", "remember",
        "remind", "remote", "remove", "render", "repair", "repeat", "replace", "reply",
        "report", "represent", "request", "require", "rescue", "research", "resemble", "reserve",
        "resist", "resolve", "resort", "resource", "respect", "respond", "rest", "result",
        "retain", "retire", "return", "reveal", "revenue", "review", "reward", "rhythm",
        "rice", "rich", "ride", "right", "ring", "rise", "risk", "river",
        "road", "rock", "role", "roll", "roof", "room", "root", "rope",
        "rough", "round", "route", "royal", "rubber", "rude", "rule", "ruler",
        "rural", "rush", "sacred", "safe", "sail", "sale", "salt", "same",
        "sample", "sand", "satisfy", "save", "scale", "scene", "scheme", "school",
        "science", "score", "screen", "search", "season", "seat", "second", "secret",
        "section", "secure", "seek", "seem", "select", "self", "sell", "send",
        "senior", "sense", "sentence", "separate", "series", "serious", "servant", "serve",
        "service", "settle", "seven", "several", "severe", "shadow", "shake", "shall",
        "shame", "shape", "share", "sharp", "sheep", "sheet", "shelf", "shell",
        "shelter", "shift", "shine", "ship", "shirt", "shock", "shoe", "shoot",
        "shop", "shore", "short", "should", "shoulder", "shout", "show", "shut",
        "sick", "side", "sight", "sign", "signal", "silent", "silk", "silly",
        "silver", "similar", "simple", "since", "sing", "single", "sink", "sister",
        "site", "situation", "size", "skill", "skin", "skirt", "sleep", "slide",
        "slight", "slip", "slope", "slow", "small", "smart", "smell", "smile",
        "smoke", "smooth", "snake", "snow", "social", "society", "soft", "soil",
        "soldier", "solid", "solve", "some", "song", "soon", "sorry", "sort",
        "sound", "soup", "source", "south", "space", "spare", "speak", "special",
        "speech", "speed", "spell", "spend", "sphere", "spice", "spirit", "split",
        "sport", "spot", "spread", "spring", "square", "stable", "staff", "stage",
        "stamp", "stand", "standard", "star", "start", "state", "station", "stay",
        "steady", "steal", "steam", "steel", "steep", "stem", "step", "stick",
        "still", "stock", "stomach", "stone", "stop", "store", "storm", "story",
        "straight", "strange", "strategy", "stream", "street", "strength", "stretch", "strict",
        "strike", "string", "strip", "strong", "structure", "struggle", "student", "study",
        "stuff", "stupid", "style", "subject", "submit", "substance", "succeed", "success",
        "such", "sudden", "suffer", "sugar", "suggest", "suit", "summer", "summit",
        "supply", "support", "suppose", "sure", "surface", "surprise", "surround", "survey",
        "survive", "suspect", "sustain", "swear", "sweep", "sweet", "swim", "swing",
        "switch", "sword", "symbol", "system", "table", "tackle", "tail", "take",
        "tale", "talent", "talk", "tall", "tank", "tape", "target", "task",
        "taste", "teach", "team", "tear", "technical", "technique", "technology", "telephone",
        "telescope", "tell", "temper", "temple", "temporary", "tempt", "tend", "tender",
        "tension", "term", "terrible", "territory", "terror", "test", "text", "than",
        "thank", "that", "theater", "their", "them", "theme", "then", "theory",
        "there", "these", "thick", "thin", "thing", "think", "third", "this",
        "thorough", "those", "though", "thought", "thousand", "thread", "threat", "three",
        "throat", "through", "throw", "thumb", "thunder", "ticket", "tide", "tight",
        "time", "tiny", "title", "today", "together", "tomorrow", "tone", "tongue",
        "tonight", "tool", "tooth", "topic", "total", "touch", "tough", "tour",
        "toward", "tower", "town", "track", "trade", "tradition", "traffic", "tragic",
        "trail", "train", "transfer", "transform", "translate", "transport", "trap", "travel",
        "treasure", "treat", "treaty", "tree", "tremble", "trend", "trial", "tribe",
        "trick", "trip", "troop", "trouble", "truck", "true", "trust", "truth",
        "tube", "tune", "tunnel", "turn", "twice", "twin", "twist", "type",
        "typical", "ugly", "ultimate", "umbrella", "unable", "uncle", "under", "understand",
        "uniform", "union", "unique", "unit", "unite", "universe", "unknown", "unless",
        "unlike", "until", "unusual", "update", "upon", "upper", "urban", "urge",
        "usage", "useful", "useless", "usual", "utility", "vacant", "vacation", "valley",
        "valuable", "value", "variety", "various", "vary", "vast", "vegetable", "vehicle",
        "venture", "version", "very", "vessel", "veteran", "victim", "victory", "video",
        "view", "village", "violate", "violence", "violent", "virtual", "virtue", "virus",
        "visible", "vision", "visit", "visual", "vital", "vivid", "voice", "volcano",
        "volume", "volunteer", "vote", "voyage", "wage", "wait", "wake", "walk",
        "wall", "wander", "want", "warm", "warn", "wash", "waste", "watch",
        "water", "wave", "weak", "wealth", "weapon", "wear", "weather", "weave",
        "wedding", "week", "weigh", "weight", "welcome", "well", "west", "western",
        "what", "wheat", "wheel", "when", "where", "whether", "which", "while",
        "whisper", "white", "whole", "whom", "whose", "wide", "widow", "width",
        "wife", "wild", "will", "willing", "wind", "window", "wine", "wing",
        "winner", "winter", "wire", "wise", "wish", "with", "within", "without",
        "witness", "woman", "wonder", "wood", "word", "work", "worker", "world",
        "worry", "worse", "worst", "worth", "would", "wound", "wrap", "wrist",
        "write", "wrong", "yard", "year", "yellow", "yesterday", "yield", "young",
        "youth", "zone"
    ]
