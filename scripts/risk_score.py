# scripts/risk_score.py
import sys, json

def calculate_score(severity, criticality=1.0):
    mapping = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    base = mapping.get(severity.upper(), 1)
    return base * criticality

def main():
    # For demo: just print a fake score
    print("# Risk Report\n")
    print("File: auth.php | Severity: HIGH | Score:", calculate_score("HIGH", 2.0))

if __name__ == "__main__":
    main()
