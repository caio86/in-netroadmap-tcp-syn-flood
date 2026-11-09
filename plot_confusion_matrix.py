import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import ConfusionMatrixDisplay, confusion_matrix

df = pd.read_csv("classified.csv")

y_true = df["actual_class"]
y_pred = df["predicted_class"]

cm = confusion_matrix(y_true, y_pred, labels=[0, 1])

disp = ConfusionMatrixDisplay(
    confusion_matrix=cm, display_labels=["Benign", "Malicious"]
)

disp.plot(values_format="d")
plt.title("BMv2 Decision Tree Confusion Matrix")
plt.savefig("confusion_matrix.png", dpi=300, bbox_inches="tight")
plt.show()
