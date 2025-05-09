import re
# A sample list of common passwords (ideally use a larger dataset or API)
COMMON_PASSWORD = {
    '123456', 'password', '12345678', 'qwerty', 'abc123', '111111', '123456789', '123123', 'admin', 'letwein'
}
def check_password_strength(password):
    score = 0
    feedback = []

    # Length
    if len(password) >= 12:
        score += 30
    elif len(password) >= 8:
        score += 20
        feedback.append("Consider using 12+ characters.")
    else:
        score += 5
        feedback.append("Password is too short. Use at least 8 characters.")

    # Chracter variety
    if re.search(r'[a-z]', password):
        score += 10
    else:
        feedback.append("Add lowercase letters.")

    if re.search(r'[A-Z]', password):
        score += 10
    else:
        feedback.append("Add uppercase letters.")
    
    if re.search(r'\d', password):
        score +=10
    else:
        feedback.append("Add numbers.")

    if re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        score += 10
    else:
        feedback.append("Add special characters.")

    # Uniqueness
    if password.lower() not in COMMON_PASSWORD:
        score += 20
    else:
        score -= 20
        feedback.append("This password is too common. Avoid using it.")

    # Final assessment
    if score >= 80:
        strength = "Strong"
    elif score >= 50:
        strength = "Moderate"
    else:
        strength = "Weak"

    return {
        "score": score,
        "strength": strength,
        "feedback": feedback,
    }

    # Example usecase
    if __name__ =="__main__":
        user_input = input("Enter a password to check its strength:")
        result = check_password_strength(user_input)
        print(f"\nPassword Strength: {result['strength']} ({result['score']}/100)")
        if result['feedback']:
            print("Suggestions:")
            for tip in result['feedback']:
                print(f"-{tip}")
