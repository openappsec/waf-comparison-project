COLORS = {
    'green': "#3BA713",
    'light_green': "#86CE02",
    'yellow': "#FFCF15",
    'orange': "#F59F3D",
    'red': "#ED4444",
}

SCORE_RANGES = {
    'excellent': 95,
    'good': 90,
    'normal': 80,
    'poor': 60,
    'bad': 0
}

DETAILED_COLOR_SCALE = [
    "#780E0E",  # 0-10
    "#8F1818",  # 10-20
    "#A92626",  # 20-30
    "#C43131",  # 30-40
    "#D53D3D",  # 40-50
    "#ED4444",  # 50-60
    "#EE6E47",  # 60-64
    "#ED8544",  # 64-68
    "#F59F3D",  # 68-72
    "#FABC36",  # 72-76
    "#FAB319",  # 76-80
    "#FAC619",  # 80-83
    "#FFCF15",  # 83-86
    "#F9DD0A",  # 86-90
    "#86CE02",  # 90-92.5
    "#9ADA03",  # 92.5-95
    "#47BA09",  # 95-97.5
    "#3BA713"  # 97.5-100
]

DETAILED_COLOR_BOUNDS = [
    0, 10, 20, 30, 40, 50, 60, 64, 68, 72, 76, 80, 83, 86, 90, 92.5, 95, 97.5, 100
]

YOUR_RESULT_TEXT = " - Your result"

BALANCED_ACCURACY_TEXTS = {
    "excellent": "The WAF's balanced accuracy score is excellent.",
    "good": "The WAF's balanced accuracy score is good.",
    "normal": "The WAF's balanced accuracy score is normal.",
    "poor": "The WAF's balanced accuracy score is poor.",
    "bad": "The WAF's balanced accuracy score is bad.",
}

WHAT_IT_MEANS_SECURITY_QUALITY_TEXTS = {
    "excellent": "The WAF blocks nearly all attacks with precise, consistent, and comprehensive protection.",
    "good": "The WAF stops most threats accurately with strong, reliable, and consistent protection.",
    "normal": "The WAF blocks common attacks but may miss advanced, complex threat scenarios.",
    "poor": "The WAF allows many threats through, reducing protection and increasing overall exposure.",
    "bad": "The WAF fails to block attacks, leaving systems exposed to severe exploitation.",
}

WHAT_IT_MEANS_DETECTION_QUALITY_TEXTS = {
    "excellent": "Handles legitimate traffic flawlessly, ensuring seamless access and full availability.",
    "good": "Accurately allows legitimate traffic with strong accuracy and minimal interference.",
    "normal": "Typically identifies legitimate traffic correctly, but may occasionally misclassify valid requests.",
    "poor": "Frequently disrupts legitimate access, causing noticeable disruption and reduced service reliability.",
    "bad": "Incorrectly blocks most legitimate traffic, severely impacting accessibility and overall availability.",
}

WHAT_TO_DO_BALANCED_ACCURACY_TEXTS = {
    "excellent": "Keep the current effective rules and policies, monitoring for changes to maintain stability and consistency.",
    "good": "Validate existing rules and policies to keep the good balance, then rerun the tool to ensure best coverage.",
    "normal": "Review the configuration for alignment with security goals and update misaligned rules, then rerun the tool to ensure best coverage.",
    "poor": "Identify and fix misconfigurations, outdated rules, or policy gaps, then rerun the tool to ensure best coverage.",
    "bad": "Reevaluate the WAF solution and insufficient protection policies for a better fit, then rerun the tool to ensure best coverage."
}

GAUGE_SECURITY_QUALITY_TEXTS = {
    "excellent": "The WAF blocks nearly all malicious traffic with precise and consistent detection.",
    "good": "The WAF blocks most attack attempts accurately, with minimal missed threats.",
    "normal": "The WAF blocks common attacks but may fail to identify more advanced or evasive threats.",
    "poor": "The WAF struggles to block a significant portion of malicious activity, reducing overall protection.",
    "bad": "The WAF fails to block most malicious traffic, leaving the system highly exposed.",
}

GAUGE_DETECTION_QUALITY_TEXTS = {
    "excellent": "The WAF allows legitimate traffic flawlessly, ensuring minimal disruption and delivering exceptional precision and reliability.",
    "good": "The WAF maintains strong precision in allowing valid traffic, with minimal interference to legitimate activity.",
    "normal": "The WAF generally distinguishes valid traffic correctly but may occasionally block legitimate requests.",
    "poor": "The WAF shows inconsistent accuracy, often flagging or blocking legitimate user activity.",
    "bad": "The WAF misclassifies a large portion of legitimate traffic, severely impacting accessibility and usability.",
}

POLAR_BAR_CHART_SECURITY_QUALITY_TEXTS = {
    "excellent": "Your WAF showed excellent results blocking malicious requests across multiple attack types.",
    "good": "Your WAF showed good results blocking malicious requests across diverse attack types.",
    "normal": "Your WAF showed normal results blocking malicious requests across diverse attack types.",
    "poor": "Your WAF showed poor results blocking malicious requests across diverse attack types.",
    "bad": "Your WAF showed bad results blocking malicious requests across diverse attack types.",
}

POLAR_BAR_CHART_DETECTION_QUALITY_TEXTS = {
    "excellent": "Your WAF showed excellent results in permitting legitimate requests across multiple website categories.",
    "good": "Your WAF showed good results in permitting legitimate requests across multiple website categories.",
    "normal": "Your WAF showed normal results in permitting legitimate requests across multiple website categories.",
    "poor": "Your WAF showed poor results in permitting legitimate requests across multiple website categories.",
    "bad": "Your WAF showed bad results in permitting legitimate requests across multiple website categories.",
}
