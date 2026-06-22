import builtwith


def scan_technology(url):
    try:
        technologies = builtwith.parse(url)

        return {
            "success": True,
            "technologies": technologies
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }