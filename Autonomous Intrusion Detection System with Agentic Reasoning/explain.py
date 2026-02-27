def generate_explanation(row, prediction):
    proto = str(row.get("protocol_type",""))
    serv = str(row.get("service",""))
    flag = str(row.get("flag",""))
    src  = float(row.get("src_bytes",0))
    dst  = float(row.get("dst_bytes",0))
    cnt  = float(row.get("count",0))

    text = f"Prediction: {prediction}\n\n"

    if prediction == "Normal":
        text += "Description: Traffic appears normal with no suspicious patterns.\n"
        text += "Mitigation: Maintain regular monitoring.\n"
    elif prediction == "DoS":
        text += "Description: DoS-like behavior detected.\n"
        if src > 2000 or dst > 4000:
            text += "- High byte volume observed.\n"
        if flag in ("REJ","S0"):
            text += f"- Flag pattern {flag} suggests failed connections.\n"
        text += "Mitigation: Enable rate limiting, block offending IPs.\n"
    elif prediction == "Probe":
        text += "Description: Scanning/probing attempts detected.\n"
        if proto == "icmp" and cnt > 5:
            text += "- ICMP sweep pattern found.\n"
        text += "Mitigation: Harden services and block scanning IPs.\n"
    elif prediction == "R2L":
        text += "Description: Remote-to-local intrusion attempt.\n"
        text += "Mitigation: Review auth logs and enforce strong passwords.\n"
    elif prediction == "U2R":
        text += "Description: Privilege escalation attempt detected.\n"
        text += "Mitigation: Investigate for local exploits.\n"
    else:
        text += "Description: Unknown attack type.\nMitigation: Manual investigation needed.\n"

    return text