
def calculate_trust_score(scan_results):
    """
    Calcule le score de confiance (0-100) et la note (A-F)
    basé sur les détails du scan.
    """
    current_score = 50
    

    details = scan_results.get("score_details", [])
    
    for item in details:
        try:
            points_str = item.split(" ")[0].replace("pts:", "")
            points = int(points_str)
            current_score += points
        except (ValueError, IndexError):
            continue


    current_score = max(0, min(100, current_score))
    
    if current_score >= 90: letter = "A"
    elif current_score >= 80: letter = "B"
    elif current_score >= 60: letter = "C"
    elif current_score >= 40: letter = "D"
    else: letter = "F"

    return {
        "numeric": current_score,
        "letter": letter
    }