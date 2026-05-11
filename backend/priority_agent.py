def assign_priority(severity):

    if severity == "Critical":
        return "P1"

    elif severity == "High":
        return "P2"

    elif severity == "Medium":
        return "P3"

    return "P4"