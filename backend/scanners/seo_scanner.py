import requests
from bs4 import BeautifulSoup


def scan_seo(url):

    try:

        headers = {
            "User-Agent":
            "Mozilla/5.0"
        }

        response = requests.get(
            url,
            headers=headers,
            timeout=10
        )

        response.raise_for_status()

        soup = BeautifulSoup(
            response.text,
            "html.parser"
        )

        # =========================
        # TITLE
        # =========================

        title = (
            soup.title.string.strip()
            if soup.title and soup.title.string
            else None
        )

        # =========================
        # META DESCRIPTION
        # =========================

        meta_tag = soup.find(
            "meta",
            attrs={"name": "description"}
        )

        meta_description = (
            meta_tag.get("content").strip() # type: ignore
            if meta_tag and meta_tag.get("content")
            else None
        )

        # =========================
        # H1 TAGS
        # =========================

        h1_tags = soup.find_all("h1")
        
        h1_texts = [
            h1.get_text(strip=True)
            for h1 in h1_tags
            if h1.get_text(strip=True)
        ]

        # =========================
        # IMAGES WITHOUT ALT
        # =========================

        images = soup.find_all("img")

        missing_alt = 0

        for img in images:

            alt = img.get("alt")

            if alt is None or alt.strip() == "": # type: ignore
                missing_alt += 1

        # =========================
        # DEEP DIVE SEO ANALYSIS
        # =========================
        
        # Canonical
        canonical_tag = soup.find("link", rel="canonical")
        canonical_url = canonical_tag.get("href") if canonical_tag else None

        # Robots meta
        robots_tag = soup.find("meta", attrs={"name": "robots"})
        robots_content = robots_tag.get("content") if robots_tag else None

        # Viewport (mobile-friendliness signal)
        has_viewport = soup.find("meta", attrs={"name": "viewport"}) is not None

        # Open Graph tags
        og_title = soup.find("meta", property="og:title")
        og_description = soup.find("meta", property="og:description")
        og_image = soup.find("meta", property="og:image")

        # Word count
        word_count = len(soup.get_text().split())

        # Link analysis
        from urllib.parse import urlparse as up
        base_domain = up(url).netloc
        internal_links, external_links = 0, 0
        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith("http"):
                if up(href).netloc == base_domain:
                    internal_links += 1
                else:
                    external_links += 1
            elif href.startswith("/") or href.startswith("./") or href.startswith("../"):
                internal_links += 1

        # =========================
        # RETURN DATA
        # =========================

        return {

            "success": True,

            "title": title,

            "meta_description":
                meta_description,

            "meta_description_exists":
                meta_description is not None,

            "h1_count":
                len(h1_tags),

            "h1_tags":
                h1_texts,

            "missing_alt_images":
                missing_alt,

            "total_images":
                len(images),

            "canonical_url": canonical_url,
            "robots_meta": robots_content,
            "has_viewport": has_viewport,
            "og_title": og_title.get("content") if og_title else None,
            "og_description": og_description.get("content") if og_description else None,
            "og_image": og_image.get("content") if og_image else None,
            "word_count": word_count,
            "internal_links": internal_links,
            "external_links": external_links
        }

    except requests.exceptions.Timeout:

        return {
            "success": False,
            "error": "Request timeout"
        }

    except requests.exceptions.ConnectionError:

        return {
            "success": False,
            "error": "Connection error"
        }

    except requests.exceptions.HTTPError as e:

        return {
            "success": False,
            "error": f"HTTP error: {str(e)}"
        }

    except Exception as e:

        return {
            "success": False,
            "error": str(e)
        }