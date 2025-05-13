import pandas as pd
from urllib.parse import urlparse
import re
from bs4 import BeautifulSoup
import whois 
import urllib.request
import time
import socket
from urllib.error import HTTPError, URLError
from datetime import datetime
import warnings
import tldextract

class FeatureExtraction:
    def __init__(self):
        pass

    def getProtocol(self, url):
        return urlparse(url).scheme

    def getDomain(self, url):
        return urlparse(url).netloc

    def getPath(self, url):
        return urlparse(url).path

    def havingIP(self, url):
        try:
            hostname = urlparse(url).netloc
            match = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", hostname)
            return 1 if match else 0
        except:
            return 0

    def long_url(self, url):
        try:
            url_length = len(url)
            if url_length < 54:
                return 0
            elif 54 <= url_length <= 75:
                return 2
            else:
                return 1
        except:
            return 1

    def have_at_symbol(self, url):
        try:
            return 1 if "@" in url else 0
        except:
            return 0

    def redirection(self, url):
        try:
            return 1 if "//" in urlparse(url).path else 0
        except:
            return 0

    def prefix_suffix_separation(self, url):
        try:
            return 1 if "-" in urlparse(url).netloc else 0
        except:
            return 0

    def sub_domains(self, url):
        try:
            dot_count = url.count(".")
            if dot_count < 3:
                return 0
            elif dot_count == 3:
                return 2
            else:
                return 1
        except:
            return 1

    def shortening_service(self, url):
        try:
            match = re.search(
                r'bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                r'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                r'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                r'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in|'
                r'db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|tinyurl\.com|ity\.im|q\.gs|po\.st|bc\.vc|'
                r'twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com|'
                r'scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|link\.zip\.net',
                url)
            return 1 if match else 0
        except:
            return 0

    def web_traffic(self, url):
        try:
            domain = urlparse(url).netloc
            if not domain:
                return 1
            socket.gethostbyname(domain)
            return 1
        except (socket.gaierror, URLError, socket.timeout):
            return 1

    def safe_whois_lookup(self, domain):
        try:
            return whois.whois(domain)
        except Exception as e:
            print(f"WHOIS lookup failed for {domain}: {str(e)}")
            return None

    def domain_registration_length(self, url):
        try:
            domain = urlparse(url).netloc
            if not domain:
                return 1

            domain_info = self.safe_whois_lookup(domain)
            if not domain_info:
                return 1

            expiration_date = domain_info.expiration_date
            today = datetime.now()

            if expiration_date is None:
                return 1

            # Handle multiple expiration dates
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            # Parse string dates
            if isinstance(expiration_date, str):
                try:
                    expiration_date = datetime.strptime(expiration_date.split(' ')[0], '%Y-%m-%d')
                except:
                    return 2

            registration_length = (expiration_date - today).days
            return 1 if registration_length <= 365 else 0

        except Exception as e:
            print(f"Domain registration error: {str(e)}")
            return 1

    def age_domain(self, url):
        try:
            domain = urlparse(url).netloc
            if not domain:
                return 1

            domain_info = self.safe_whois_lookup(domain)
            if not domain_info:
                return 1

            creation_date = domain_info.creation_date
            expiration_date = domain_info.expiration_date

            if creation_date is None or expiration_date is None:
                return 1

            # Handle lists of dates
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]

            # Parse string dates
            if isinstance(creation_date, str):
                creation_date = datetime.strptime(creation_date.split(' ')[0], '%Y-%m-%d')
            if isinstance(expiration_date, str):
                expiration_date = datetime.strptime(expiration_date.split(' ')[0], '%Y-%m-%d')

            age_days = (expiration_date - creation_date).days
            return 1 if (age_days / 30) < 6 else 0

        except Exception as e:
            print(f"Domain age error: {str(e)}")
            return 1

    def dns_record(self, url):
        try:
            domain = urlparse(url).netloc
            if not domain:
                return 1
            self.safe_whois_lookup(domain)
            return 0
        except:
            return 1

    def statistical_report(self, url):
        try:
            hostname = urlparse(url).netloc
            if not hostname:
                return 1

            ip_address = socket.gethostbyname(hostname)

            url_match = re.search(
                r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly',
                url)
            ip_match = re.search(
                r'146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|'
                r'181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                r'107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|'
                r'107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                r'118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|'
                r'141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                r'216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|'
                r'213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                r'34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|'
                r'198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|'
                r'209\.99\.17\.27|216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|54\.86\.225\.156|'
                r'54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
                ip_address)

            return 1 if url_match or ip_match else 0
        except:
            return 1

    def https_token(self, url):
        try:
            return 1 if re.search(r"https?://.*(http|https)", url) else 0
        except:
            return 1
            
    def nb_dots(self, url):
        """Count number of dots in URL"""
        try:
            return url.count('.')
        except:
            return 0
            
    def nb_qm(self, url):
        """Count number of question marks in URL"""
        try:
            return url.count('?')
        except:
            return 0
            
    def nb_and(self, url):
        """Count number of ampersands in URL"""
        try:
            return url.count('&')
        except:
            return 0
            
    def nb_eq(self, url):
        """Count number of equal signs in URL"""
        try:
            return url.count('=')
        except:
            return 0
            
    def ratio_digits_url(self, url):
        """Calculate ratio of digits in URL"""
        try:
            digits = sum(c.isdigit() for c in url)
            length = len(url)
            return digits / length if length > 0 else 0
        except:
            return 0
            
    def punycode(self, url):
        """Check if URL contains punycode"""
        try:
            domain = urlparse(url).netloc
            return 1 if 'xn--' in domain else 0
        except:
            return 0
            
    def domain_in_brand(self, url, brand=None):
        """Check if brand name is in domain"""
        try:
            if brand is None:
                # You might want to pass a brand name or implement a default logic
                return 0
            domain = urlparse(url).netloc.lower()
            return 1 if brand.lower() in domain else 0
        except:
            return 0
            
    def brand_in_path(self, url, brand=None):
        """Check if brand name is in path"""
        try:
            if brand is None:
                # You might want to pass a brand name or implement a default logic
                return 0
            path = urlparse(url).path.lower()
            return 1 if brand.lower() in path else 0
        except:
            return 0
            
    def suspicious_tld(self, url):
        """Check if TLD is suspicious"""
        suspicious_tlds = {'zip', 'cricket', 'link', 'work', 'party', 'gq', 'kim', 
                          'country', 'science', 'tk', 'ml', 'ga', 'cf', 'review'}
        try:
            ext = tldextract.extract(url)
            return 1 if ext.suffix in suspicious_tlds else 0
        except:
            return 0


def getAttributess(url):
    try:
        if not url:
            return None

        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        fe = FeatureExtraction()

        # EXACT ORDER as shown in model's expected features:
        features = [
            fe.have_at_symbol(url),    # Having_@_symbol
            fe.havingIP(url),          # Having_IP
            fe.prefix_suffix_separation(url),  # Prefix_suffix_separation
            fe.redirection(url),       # Redirection_//_symbol
            fe.sub_domains(url),       # Sub_domains
            fe.long_url(url),          # URL_Length
            fe.age_domain(url),        # age_domain
            fe.dns_record(url),       # dns_record
            fe.domain_registration_length(url),  # domain_registration_length
            fe.https_token(url),       # http_tokens
            fe.statistical_report(url),  # statistical_report
            fe.shortening_service(url), # tiny_url
            fe.web_traffic(url),       # web_traffic
            fe.nb_dots(url),          # nb_dots
            fe.nb_qm(url),            # nb_qm
            fe.nb_and(url),           # nb_and
            fe.nb_eq(url),             # nb_eq
            fe.ratio_digits_url(url),  # ratio_digits_url
            fe.punycode(url),          # punycode
            fe.domain_in_brand(url),   # domain_in_brand
            fe.brand_in_path(url),     # brand_in_path
            fe.suspicious_tld(url)     # suspicious_tld
        ]
        
        # EXACT ORDER as model expects:
        columns = [
            'Having_@_symbol',
            'Having_IP',
            'Prefix_suffix_separation',
            'Redirection_//_symbol',
            'Sub_domains',
            'URL_Length',
            'age_domain',
            'dns_record',
            'domain_registration_length',
            'http_tokens',
            'statistical_report',
            'tiny_url',
            'web_traffic',
            'nb_dots',
            'nb_qm',
            'nb_and',
            'nb_eq',
            'ratio_digits_url',
            'punycode',
            'domain_in_brand',
            'brand_in_path',
            'suspecious_tld'
        ]
        
        data = pd.DataFrame([features], columns=columns)
        return data

    except Exception as e:
        print(f"Error in getAttributess: {str(e)}")
        return None