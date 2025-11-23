import itertools
import tldextract
from typing import List, Set
from urllib.parse import urlparse


class DomainVariationGenerator:
    """Generate phishing domain variations"""
    
    # Comprehensive TLD list - ALL major TLDs
    COMMON_TLDS = [
        # Generic TLDs
        'com', 'net', 'org', 'info', 'biz', 'name', 'pro', 'mobi', 'tel', 'asia',
        'xxx', 'travel', 'jobs', 'coop', 'aero', 'cat', 'museum', 'post',
        
        # New gTLDs - Popular
        'xyz', 'top', 'site', 'online', 'club', 'shop', 'store', 'tech', 'app',
        'blog', 'news', 'media', 'email', 'web', 'website', 'space', 'live',
        'studio', 'digital', 'network', 'systems', 'solutions', 'services',
        'company', 'business', 'enterprises', 'management', 'consulting',
        'marketing', 'technology', 'software', 'cloud', 'hosting', 'domains',
        'games', 'play', 'casino', 'bet', 'poker', 'racing', 'sport', 'fitness',
        'health', 'care', 'dental', 'clinic', 'surgery', 'hospital', 'pharmacy',
        'education', 'academy', 'training', 'university', 'college', 'school',
        'finance', 'bank', 'credit', 'loan', 'money', 'cash', 'capital', 'invest',
        'insurance', 'financial', 'accountant', 'tax', 'fund', 'trading',
        'food', 'restaurant', 'bar', 'cafe', 'menu', 'recipes', 'cooking',
        'fashion', 'clothing', 'shoes', 'jewelry', 'beauty', 'boutique',
        'realestate', 'property', 'homes', 'house', 'apartments', 'rentals',
        'travel', 'hotel', 'flights', 'tours', 'vacation', 'cruise', 'tickets',
        'auto', 'car', 'cars', 'bike', 'motorcycles', 'parts', 'repair',
        'photo', 'photography', 'pics', 'pictures', 'gallery', 'camera',
        'video', 'film', 'movie', 'tv', 'audio', 'music', 'band', 'radio',
        'art', 'design', 'graphics', 'creative', 'artist', 'gallery',
        'social', 'community', 'forum', 'chat', 'dating', 'singles', 'wedding',
        'legal', 'lawyer', 'attorney', 'law', 'attorney', 'claims',
        'construction', 'builders', 'contractors', 'plumbing', 'electrical',
        'security', 'protection', 'safety', 'alarm', 'defense',
        'pizza', 'wine', 'beer', 'vodka', 'coffee', 'tea',
        'black', 'blue', 'green', 'pink', 'red', 'gold', 'silver',
        'one', 'plus', 'best', 'new', 'now', 'today', 'world', 'global',
        'life', 'love', 'fun', 'cool', 'vip', 'guru', 'ninja', 'expert',
        'click', 'link', 'download', 'stream', 'watch', 'buy', 'sale',
        'discount', 'deals', 'coupons', 'promo', 'offers',
        
        # Country Code TLDs (ccTLDs) - Major countries
        'in', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'it', 'es', 'nl', 'be', 'ch', 'at',
        'se', 'no', 'dk', 'fi', 'pl', 'cz', 'hu', 'ro', 'bg', 'gr', 'pt', 'ie',
        'ru', 'ua', 'by', 'kz', 'uz', 'am', 'az', 'ge', 'md', 'tj', 'tm',
        'cn', 'jp', 'kr', 'tw', 'hk', 'sg', 'my', 'th', 'vn', 'ph', 'id',
        'pk', 'bd', 'lk', 'np', 'bt', 'mv', 'af', 'ir', 'iq', 'il',
        'sa', 'ae', 'qa', 'kw', 'bh', 'om', 'ye', 'jo', 'lb', 'sy', 'tr',
        'eg', 'ma', 'dz', 'tn', 'ly', 'sd', 'et', 'ke', 'tz', 'ug', 'za',
        'ng', 'gh', 'ci', 'sn', 'cm', 'ao', 'mz', 'zw', 'na', 'bw', 'zm',
        'br', 'mx', 'ar', 'cl', 'co', 'pe', 've', 'ec', 'bo', 'py', 'uy',
        'cr', 'pa', 'gt', 'hn', 'sv', 'ni', 'do', 'cu', 'jm', 'ht', 'tt',
        'nz', 'fj', 'pg', 'nc', 'pf', 'ck', 'ws', 'to', 'tv', 'nu', 'tk'
        
        # Alternative TLDs
        'io', 'co', 'me', 'ai', 'gg', 'im', 'je', 'ac', 'sh', 'cx', 'cc', 'ws',
        'bz', 'ag', 'sc', 'mn', 'la', 'fm', 'am', 'cd', 'dj', 'to', 'tk', 'ml',
        'ga', 'cf', 'gq', 'pw', 'vu', 'sb', 'ki', 'nr', 'gl', 'fo', 'aw',
        
        # Regional/Special TLDs
        'eu', 'asia', 'africa', 'lat', 'arab',
        
        # Popular/Trendy TLDs
        'design', 'dev', 'run', 'codes', 'work', 'agency', 'directory',
        'support', 'help', 'guide', 'center', 'wiki', 'tips', 'zone',
        'today', 'reviews', 'feedback', 'press', 'report', 'events',
        'foundation', 'institute', 'center', 'international', 'group'
    ]
    
    # Typosquatting character substitutions - Only visually similar & look-alike characters
    CHAR_SUBSTITUTIONS = {
        'a': ['@', '4', 'q'],  # @ symbol, 4 looks like A, q similar shape
        'b': ['8', 'd', 'p'],  # 8 looks like B, d/p similar shapes
        'c': ['e', '('],  # e similar, ( shape
        'd': ['b', 'cl'],  # b mirror, cl combination
        'e': ['3', 'c'],  # 3 common substitution, c similar
        'f': ['t'],  # t similar shape
        'g': ['9', 'q'],  # 9 looks like g, q similar
        'h': ['n'],  # n similar when lowercase
        'i': ['1', 'l', '!', 'j'],  # 1, l, ! very common, j similar
        'j': ['i'],  # i similar
        'k': ['x'],  # x similar shape
        'l': ['1', 'i', '|'],  # 1, i, | very similar
        'm': ['n', 'rn'],  # n similar, rn can look like m
        'n': ['m', 'h'],  # m similar, h similar
        'o': ['0', 'q'],  # 0 very common, q similar
        'p': ['b', 'd'],  # b/d similar shapes
        'q': ['g', 'o'],  # g/o similar shapes
        'r': ['n'],  # n similar in some fonts
        's': ['5', '$', 'z'],  # 5, $ common, z similar
        't': ['f', '+'],  # f similar, + shape
        'u': ['v', 'w'],  # v/w similar shapes
        'v': ['u', 'w'],  # u/w similar shapes
        'w': ['vv', 'u'],  # vv combination, u similar
        'x': ['k'],  # k similar shape
        'y': ['v'],  # v similar
        'z': ['s', '2'],  # s similar, 2 looks like Z
    }
    
    # IDN Homograph character mappings (Unicode lookalikes)
    IDN_HOMOGRAPHS = {
        'a': ['а', 'ɑ', 'α', 'а'],  # Cyrillic, Greek, Latin lookalikes
        'b': ['Ь', 'ь', 'Ƅ', 'ƅ'],  # Cyrillic, Latin lookalikes
        'c': ['с', 'ϲ', 'Ϲ', 'ⅽ'],  # Cyrillic, Greek, Latin lookalikes
        'd': ['ԁ', 'ⅾ', 'ⅆ', 'ⅅ'],  # Cyrillic, Latin lookalikes
        'e': ['е', 'е', 'ε', 'ε'],  # Cyrillic, Greek lookalikes
        'f': ['Ϝ', 'ϝ', 'ƒ', 'ſ'],  # Greek, Latin lookalikes
        'g': ['ɡ', 'ց', 'ց', 'ց'],  # Latin, Armenian lookalikes
        'h': ['һ', 'հ', 'հ', 'հ'],  # Cyrillic, Armenian lookalikes
        'i': ['і', 'і', 'ι', 'ι'],  # Cyrillic, Greek lookalikes
        'j': ['ј', 'ј', 'ϳ', 'ϳ'],  # Cyrillic, Greek lookalikes
        'k': ['к', 'к', 'κ', 'κ'],  # Cyrillic, Greek lookalikes
        'l': ['l', 'l', 'ι', 'ι'],  # Latin, Greek lookalikes
        'm': ['м', 'м', 'μ', 'μ'],  # Cyrillic, Greek lookalikes
        'n': ['п', 'п', 'η', 'η'],  # Cyrillic, Greek lookalikes
        'o': ['о', 'о', 'ο', 'ο'],  # Cyrillic, Greek lookalikes
        'p': ['р', 'р', 'ρ', 'ρ'],  # Cyrillic, Greek lookalikes
        'q': ['ԛ', 'ԛ', 'ԛ', 'ԛ'],  # Cyrillic lookalikes
        'r': ['г', 'г', 'г', 'г'],  # Cyrillic lookalikes
        's': ['ѕ', 'ѕ', 'ѕ', 'ѕ'],  # Cyrillic lookalikes
        't': ['т', 'т', 'τ', 'τ'],  # Cyrillic, Greek lookalikes
        'u': ['υ', 'υ', 'υ', 'υ'],  # Greek lookalikes
        'v': ['ν', 'ν', 'ν', 'ν'],  # Greek lookalikes
        'w': ['ω', 'ω', 'ω', 'ω'],  # Greek lookalikes
        'x': ['х', 'х', 'χ', 'χ'],  # Cyrillic, Greek lookalikes
        'y': ['у', 'у', 'γ', 'γ'],  # Cyrillic, Greek lookalikes
        'z': ['z', 'z', 'z', 'z'],  # Latin lookalikes
    }
    
    # Keyboard proximity substitutions
    KEYBOARD_PROXIMITY = {
        'a': ['s', 'q', 'w', 'z'],
        'b': ['v', 'g', 'h', 'n'],
        'c': ['x', 'd', 'f', 'v'],
        'd': ['s', 'e', 'r', 'f', 'c', 'x'],
        'e': ['w', 'r', 'd', 's'],
        'f': ['d', 'r', 't', 'g', 'v', 'c'],
        'g': ['f', 't', 'y', 'h', 'b', 'v'],
        'h': ['g', 'y', 'u', 'j', 'n', 'b'],
        'i': ['u', 'o', 'k', 'j'],
        'j': ['h', 'u', 'i', 'k', 'n', 'm'],
        'k': ['j', 'i', 'o', 'l', 'm'],
        'l': ['k', 'o', 'p'],
        'm': ['n', 'j', 'k'],
        'n': ['b', 'h', 'j', 'm'],
        'o': ['i', 'p', 'l', 'k'],
        'p': ['o', 'l'],
        'q': ['w', 'a'],
        'r': ['e', 't', 'f', 'd'],
        's': ['a', 'w', 'e', 'd', 'x', 'z'],
        't': ['r', 'y', 'g', 'f'],
        'u': ['y', 'i', 'j', 'h'],
        'v': ['c', 'f', 'g', 'b'],
        'w': ['q', 'e', 's', 'a'],
        'x': ['z', 's', 'd', 'c'],
        'y': ['t', 'u', 'h', 'g'],
        'z': ['a', 's', 'x'],
    }
    
    # Combosquatting keywords
    COMBO_KEYWORDS = [
        'secure', 'login', 'verify', 'account', 'auth', 'user',
        'online', 'banking', 'portal', 'web', 'mail', 'service',
        'support', 'help', 'official', 'app', 'mobile'
    ]
    
    # Comprehensive Homograph characters (lookalikes) for IDN attacks
    HOMOGRAPHS = {
        'a': ['а', 'ạ', 'ă', 'ā', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ'],  # Cyrillic and accented
        'b': ['Ь', 'ь', 'ƃ', 'ƅ'],
        'c': ['с', 'ċ', 'ç', 'ć', 'č', 'ĉ', 'ċ', 'ƈ'],
        'd': ['ԁ', 'đ', 'ď', 'ƌ', 'Ɗ'],
        'e': ['е', 'ė', 'é', 'è', 'ê', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě', 'Ə'],
        'f': ['ƒ', 'ſ'],
        'g': ['ɡ', 'ġ', 'ģ', 'ĝ', 'ğ', 'ǧ', 'ǵ', 'Ɠ'],
        'h': ['һ', 'ĥ', 'ħ', 'ƕ'],
        'i': ['і', 'ı', 'í', 'ì', 'î', 'ï', 'ī', 'ĭ', 'į', 'ı', 'Ɨ'],
        'j': ['ј', 'ĵ', 'ǰ', 'ɉ'],
        'k': ['к', 'ķ', 'ĸ', 'ǩ', 'ƙ'],
        'l': ['l', 'ĺ', 'ļ', 'ľ', 'ŀ', 'ł', 'ƚ'],
        'm': ['м', 'ɱ', 'Ɯ'],
        'n': ['п', 'ń', 'ņ', 'ň', 'ŉ', 'ŋ', 'ƞ', 'Ɲ'],
        'o': ['о', 'ọ', 'ó', 'ò', 'ô', 'õ', 'ö', 'ø', 'ō', 'ŏ', 'ő', 'Ɵ', 'Ơ'],
        'p': ['р', 'ƥ', 'Ƥ'],
        'q': ['ԛ', 'ɋ'],
        'r': ['г', 'ŕ', 'ŗ', 'ř', 'Ʀ'],
        's': ['ѕ', 'ś', 'ŝ', 'ş', 'š', 'ƨ', 'Ƨ'],
        't': ['т', 'ť', 'ţ', 'ŧ', 'ƫ', 'Ƭ'],
        'u': ['υ', 'ú', 'ù', 'û', 'ü', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'Ʊ', 'Ʋ'],
        'v': ['ν', 'ѵ', 'Ʋ'],
        'w': ['ω', 'ŵ', 'Ɯ'],
        'x': ['х', 'χ', 'Ƶ'],
        'y': ['у', 'ý', 'ÿ', 'ŷ', 'ƴ'],
        'z': ['ź', 'ż', 'ž', 'ƶ', 'Ƶ'],
        '0': ['O', 'о', 'Ο', 'ο', 'О', 'о'],
        '1': ['l', 'I', '|', 'ι', 'Ι', 'І', 'і'],
        '2': ['ƻ', 'ƨ'],
        '3': ['Ʒ', 'Ƹ'],
        '4': ['Ƽ'],
        '5': ['ƽ', 'ƾ'],
        '6': ['ƅ'],
        '7': ['ƻ'],
        '8': ['Ƹ', 'ƹ'],
        '9': ['ƺ', 'ƻ'],
    }
    
    def __init__(self, domain: str):
        """Initialize with a legitimate domain"""
        self.original_domain = domain.lower().strip()
        
        # Parse domain
        extracted = tldextract.extract(self.original_domain)
        self.domain_name = extracted.domain
        self.tld = extracted.suffix
        self.subdomain = extracted.subdomain
        
    def generate_all_variations(self, max_variations: int = 100000) -> List[dict]:
        """Generate all types of variations with comprehensive TLDs and alphabet substitutions"""
        variations = []  # Use list to preserve all variations
        
        # Add all variation types
        variations.extend(self._typosquatting_omission())
        variations.extend(self._typosquatting_repetition())
        variations.extend(self._typosquatting_substitution())
        variations.extend(self._typosquatting_insertion())
        variations.extend(self._idn_homograph_attacks())
        variations.extend(self._keyboard_proximity())
        variations.extend(self._combosquatting())
        variations.extend(self._tld_variations())
        variations.extend(self._homograph_attack())
        variations.extend(self._subdomain_variations())
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variations = []
        for var in variations:
            if var['domain'] not in seen:
                seen.add(var['domain'])
                unique_variations.append(var)
        
        # Limit to max_variations
        return unique_variations[:max_variations]
    
    def _typosquatting_omission(self) -> List[dict]:
        """Character omission: example.com -> exmple.com"""
        variations = []
        for i in range(len(self.domain_name)):
            if len(self.domain_name) > 3:  # Don't make it too short
                variation = self.domain_name[:i] + self.domain_name[i+1:]
                full_domain = f"{variation}.{self.tld}"
                variations.append(self._create_variation_dict(full_domain, 'typosquatting_omission'))
        return variations
    
    def _typosquatting_repetition(self) -> List[dict]:
        """Character repetition: example.com -> exxample.com"""
        variations = []
        for i in range(len(self.domain_name)):
            variation = self.domain_name[:i] + self.domain_name[i] + self.domain_name[i:]
            full_domain = f"{variation}.{self.tld}"
            variations.append(self._create_variation_dict(full_domain, 'typosquatting_repetition'))
        return variations
    
    def _typosquatting_substitution(self) -> List[dict]:
        """Character substitution: example.com -> 3xample.com"""
        variations = []
        for i, char in enumerate(self.domain_name):
            if char in self.CHAR_SUBSTITUTIONS:
                for sub_char in self.CHAR_SUBSTITUTIONS[char]:
                    variation = self.domain_name[:i] + sub_char + self.domain_name[i+1:]
                    full_domain = f"{variation}.{self.tld}"
                    variations.append(self._create_variation_dict(full_domain, 'typosquatting_substitution'))
        return variations
    
    def _typosquatting_insertion(self) -> List[dict]:
        """Character insertion: example.com -> exaample.com"""
        variations = []
        for i in range(len(self.domain_name)):
            # Insert same character
            variation = self.domain_name[:i] + self.domain_name[i] + self.domain_name[i:]
            full_domain = f"{variation}.{self.tld}"
            variations.append(self._create_variation_dict(full_domain, 'typosquatting_insertion'))
        return variations
    
    def _keyboard_proximity(self) -> List[dict]:
        """Keyboard proximity: example.com -> exampke.com"""
        variations = []
        for i, char in enumerate(self.domain_name):
            if char in self.KEYBOARD_PROXIMITY:
                for prox_char in self.KEYBOARD_PROXIMITY[char]:  # All proximity chars
                    if prox_char != char:  # Skip if it's the same character
                        variation = self.domain_name[:i] + prox_char + self.domain_name[i+1:]
                        full_domain = f"{variation}.{self.tld}"
                        variations.append(self._create_variation_dict(full_domain, 'keyboard_proximity'))
        return variations
    
    def _combosquatting(self) -> List[dict]:
        """Combosquatting: example.com -> secure-example.com, example-login.com"""
        variations = []
        for keyword in self.COMBO_KEYWORDS:  # All keywords
            # Prefix
            variations.append(self._create_variation_dict(
                f"{keyword}-{self.domain_name}.{self.tld}", 
                'combosquatting_prefix'
            ))
            variations.append(self._create_variation_dict(
                f"{keyword}{self.domain_name}.{self.tld}", 
                'combosquatting_prefix'
            ))
            
            # Suffix
            variations.append(self._create_variation_dict(
                f"{self.domain_name}-{keyword}.{self.tld}", 
                'combosquatting_suffix'
            ))
            variations.append(self._create_variation_dict(
                f"{self.domain_name}{keyword}.{self.tld}", 
                'combosquatting_suffix'
            ))
        return variations
    
    def _tld_variations(self) -> List[dict]:
        """TLD variations: example.com -> example.net"""
        variations = []
        for tld in self.COMMON_TLDS:
            if tld != self.tld:
                variations.append(self._create_variation_dict(
                    f"{self.domain_name}.{tld}", 
                    'tld_variation'
                ))
        return variations
    
    def _homograph_attack(self) -> List[dict]:
        """Homograph/IDN attack: example.com -> еxample.com (е is Cyrillic)"""
        variations = []
        for i, char in enumerate(self.domain_name):
            if char in self.HOMOGRAPHS:
                for homo_char in self.HOMOGRAPHS[char]:  # All homograph chars
                    variation = self.domain_name[:i] + homo_char + self.domain_name[i+1:]
                    full_domain = f"{variation}.{self.tld}"
                    variations.append(self._create_variation_dict(full_domain, 'homograph_attack'))
        return variations
    
    def _subdomain_variations(self) -> List[dict]:
        """Subdomain variations: example.com -> secure.example.com (excluding www)"""
        variations = []
        # Exclude 'www' as it's often the legitimate domain
        subdomains = ['secure', 'login', 'auth', 'mail', 'webmail', 'admin', 'portal', 'app', 'api']
        
        for subdomain in subdomains:
            variations.append(self._create_variation_dict(
                f"{subdomain}.{self.domain_name}.{self.tld}", 
                'subdomain_variation'
            ))
        return variations
    
    def _idn_homograph_attacks(self) -> List[dict]:
        """Generate IDN homograph attacks using Unicode lookalike characters"""
        variations = []
        
        # Generate variations by replacing each character with its homograph
        for i, char in enumerate(self.domain_name):
            if char.lower() in self.IDN_HOMOGRAPHS:
                homographs = self.IDN_HOMOGRAPHS[char.lower()]
                for homograph in homographs[:2]:  # Limit to 2 per character to avoid too many variations
                    new_domain = self.domain_name[:i] + homograph + self.domain_name[i+1:]
                    variations.append(self._create_variation_dict(
                        f"{new_domain}.{self.tld}", 
                        'idn_homograph'
                    ))
        
        return variations
    
    def _create_variation_dict(self, domain: str, variation_type: str) -> dict:
        """Create a variation dictionary"""
        return {'domain': domain, 'type': variation_type}


def generate_variations_for_domain(domain: str, max_variations: int = 100000) -> List[dict]:
    """Helper function to generate variations for a domain with comprehensive coverage"""
    generator = DomainVariationGenerator(domain)
    return generator.generate_all_variations(max_variations)

