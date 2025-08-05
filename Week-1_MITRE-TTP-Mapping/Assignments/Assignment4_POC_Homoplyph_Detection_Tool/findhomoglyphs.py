import re
import sys

try:
    import homoglyphs as hg
except ImportError:
    print("Please install the homoglyphs package: pip install homoglyphs")
    sys.exit(1)

def extract_links_from_file(filepath):
    """
    Extract possible URLs/domains from text using regex.
    """
    with open(filepath, "r", encoding="utf-8") as f:
        text = f.read()
    
    url_pattern = re.compile(
        r'((?:https?://|www\.)[^\s]+|[a-zA-Z0-9-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?)'
    )

    return url_pattern.findall(text)

def is_link_suspicious(link, homoglyphs_obj):
    """
    Returns True if the link contains homoglyphs (visually confusing characters).
    """
    ascii_versions = homoglyphs_obj.to_ascii(link)
    return bool(ascii_versions and (link not in ascii_versions))

def check_links(filepath):
    """
    Main function: loads links, checks each, and displays results.
    """
    homoglyphs_obj = hg.Homoglyphs(languages={'en', 'ru', 'el'})
    links = extract_links_from_file(filepath)
    suspicious_links = [
        link for link in links if is_link_suspicious(link, homoglyphs_obj)
    ]

    print(f"Links found ({len(links)}):")
    for link in links:
        print("  ", link)
    print("\nSuspicious (potentially fake) links:")
    if suspicious_links:
        for link in suspicious_links:
            print("  ", link)
    else:
        print("  None detected.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python homoglyph_checker.py your_file.txt")
        sys.exit(1)
    check_links(sys.argv[1])
