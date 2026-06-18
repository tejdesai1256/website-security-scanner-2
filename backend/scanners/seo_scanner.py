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

            "missing_alt_images":
                missing_alt,

            "total_images":
                len(images)
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