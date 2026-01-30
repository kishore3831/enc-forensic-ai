def calculate_suspicion_score(packet):
    score = 0

    if packet["Entropy"] > 7:
        score += 50

    if packet["Destination Port"] not in [80, 443]:
        score += 25

    if packet["Payload Size"] > 1000:
        score += 25

    return score
