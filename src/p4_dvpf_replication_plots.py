import random
import time
from collections import Counter
import math
import matplotlib.pyplot as plt

random.seed(42)

# ------------------------------------------------------------
# Core helpers
# ------------------------------------------------------------
def shannon_entropy(items):
    counts = Counter(items)
    total = len(items)
    entropy = 0.0
    for c in counts.values():
        p = c / total
        entropy -= p * math.log2(p)
    return entropy

def max_ratio(window):
    counts = Counter(window)
    total = len(window)
    return max(counts.values()) / total

# ------------------------------------------------------------
# Traffic generation
# ------------------------------------------------------------
def generate_normal_window(num_packets=200, num_dsts=10):
    destinations = [f"10.0.0.{i}" for i in range(1, num_dsts + 1)]
    packets = [random.choice(destinations) for _ in range(num_packets)]
    return packets, 0  # 0 = normal

def generate_anomalous_window(num_packets=200, num_dsts=10, hot_prob=0.75):
    destinations = [f"10.0.0.{i}" for i in range(1, num_dsts + 1)]
    hot_dst = "10.0.0.9"
    packets = []
    for _ in range(num_packets):
        if random.random() < hot_prob:
            packets.append(hot_dst)
        else:
            packets.append(random.choice(destinations))
    return packets, 1  # 1 = anomaly

def generate_dataset(num_windows=100, anomaly_ratio=0.5, num_packets=200):
    data = []
    num_anom = int(num_windows * anomaly_ratio)
    num_norm = num_windows - num_anom

    for _ in range(num_norm):
        data.append(generate_normal_window(num_packets=num_packets))
    for _ in range(num_anom):
        data.append(generate_anomalous_window(num_packets=num_packets))

    random.shuffle(data)
    return data

# ------------------------------------------------------------
# Detection methods
# ------------------------------------------------------------
def detect_entropy(window, baseline_entropy, alpha):
    current_entropy = shannon_entropy(window)
    return 1 if abs(current_entropy - baseline_entropy) > alpha else 0

def detect_bucket_dominance(window, threshold=0.35):
    mr = max_ratio(window)
    return 1 if mr > threshold else 0

# ------------------------------------------------------------
# Metrics
# ------------------------------------------------------------
def compute_metrics(y_true, y_pred, delays_ms):
    tp = tn = fp = fn = 0
    for t, p in zip(y_true, y_pred):
        if p == 1 and t == 1:
            tp += 1
        elif p == 0 and t == 0:
            tn += 1
        elif p == 1 and t == 0:
            fp += 1
        else:
            fn += 1

    total = tp + tn + fp + fn
    accuracy = (tp + tn) / total if total else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0
    avg_delay = sum(delays_ms) / len(delays_ms) if delays_ms else 0.0

    return {
        "tp": tp,
        "tn": tn,
        "fp": fp,
        "fn": fn,
        "accuracy": accuracy,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "avg_delay_ms": avg_delay,
    }

def evaluate_method(dataset, method_name, **kwargs):
    y_true = []
    y_pred = []
    delays_ms = []

    for window, label in dataset:
        start = time.perf_counter()

        if method_name == "entropy":
            pred = detect_entropy(window, kwargs["baseline_entropy"], kwargs["alpha"])
        elif method_name == "bucket":
            pred = detect_bucket_dominance(window, kwargs["threshold"])
        else:
            raise ValueError("Unknown method")

        end = time.perf_counter()

        y_true.append(label)
        y_pred.append(pred)
        delays_ms.append((end - start) * 1000.0)

    return compute_metrics(y_true, y_pred, delays_ms)

def baseline_entropy_from_normal(num_samples=50, num_packets=200):
    entropies = []
    for _ in range(num_samples):
        window, _ = generate_normal_window(num_packets=num_packets)
        entropies.append(shannon_entropy(window))
    return sum(entropies) / len(entropies)

# ------------------------------------------------------------
# Refined visualization helpers
# ------------------------------------------------------------
def plot_window_threshold_behavior(num_windows=40, num_packets=200, threshold=0.35):
    windows = []
    labels = []
    ratios = []

    for _ in range(num_windows // 2):
        w, l = generate_normal_window(num_packets=num_packets)
        windows.append(w)
        labels.append(l)
        ratios.append(max_ratio(w))

    for _ in range(num_windows // 2):
        w, l = generate_anomalous_window(num_packets=num_packets)
        windows.append(w)
        labels.append(l)
        ratios.append(max_ratio(w))

    # keep normal first, anomaly second so the plot is visually clear
    x = list(range(1, num_windows + 1))

    plt.figure(figsize=(10, 5))
    plt.plot(x[:num_windows // 2], ratios[:num_windows // 2], marker="o", label="Normal windows")
    plt.plot(x[num_windows // 2:], ratios[num_windows // 2:], marker="s", label="Anomalous windows")
    plt.axhline(y=threshold, linestyle="--", label=f"Threshold = {threshold:.2f}")
    plt.xlabel("Window Index")
    plt.ylabel("Max Traffic Ratio")
    plt.title("Threshold Crossing: Normal vs Anomalous Traffic")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_distribution_histogram(num_samples=100, num_packets=200, threshold=0.35):
    normal_ratios = []
    anomaly_ratios = []

    for _ in range(num_samples):
        w, _ = generate_normal_window(num_packets=num_packets)
        normal_ratios.append(max_ratio(w))

        w, _ = generate_anomalous_window(num_packets=num_packets)
        anomaly_ratios.append(max_ratio(w))

    plt.figure(figsize=(10, 5))
    plt.hist(normal_ratios, bins=15, alpha=0.7, label="Normal")
    plt.hist(anomaly_ratios, bins=15, alpha=0.7, label="Anomalous")
    plt.axvline(x=threshold, linestyle="--", label=f"Threshold = {threshold:.2f}")
    plt.xlabel("Max Traffic Ratio")
    plt.ylabel("Number of Windows")
    plt.title("Distribution of Traffic Concentration")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_metrics_vs_anomaly_ratio():
    baseline_entropy = baseline_entropy_from_normal()

    anomaly_ratios = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7]
    entropy_acc = []
    bucket_acc = []
    entropy_delay = []
    bucket_delay = []
    entropy_fpr = []
    bucket_fpr = []

    for ratio in anomaly_ratios:
        dataset = generate_dataset(num_windows=200, anomaly_ratio=ratio, num_packets=200)

        entropy_metrics = evaluate_method(
            dataset,
            "entropy",
            baseline_entropy=baseline_entropy,
            alpha=0.60
        )

        bucket_metrics = evaluate_method(
            dataset,
            "bucket",
            threshold=0.35
        )

        entropy_acc.append(entropy_metrics["accuracy"])
        bucket_acc.append(bucket_metrics["accuracy"])
        entropy_delay.append(entropy_metrics["avg_delay_ms"])
        bucket_delay.append(bucket_metrics["avg_delay_ms"])
        entropy_fpr.append(entropy_metrics["false_positive_rate"])
        bucket_fpr.append(bucket_metrics["false_positive_rate"])

        print(f"\nAnomaly ratio = {ratio:.1f}")
        print("Entropy-style metrics:", entropy_metrics)
        print("Bucket-style metrics :", bucket_metrics)

    plt.figure(figsize=(8, 5))
    plt.plot(anomaly_ratios, entropy_acc, marker="o", label="Entropy-style")
    plt.plot(anomaly_ratios, bucket_acc, marker="s", label="Bucket-dominance")
    plt.xlabel("Anomalous Traffic Ratio")
    plt.ylabel("Detection Accuracy")
    plt.title("Accuracy vs Anomalous Traffic Ratio")
    plt.ylim(0.0, 1.05)
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 5))
    plt.plot(anomaly_ratios, entropy_fpr, marker="o", label="Entropy-style")
    plt.plot(anomaly_ratios, bucket_fpr, marker="s", label="Bucket-dominance")
    plt.xlabel("Anomalous Traffic Ratio")
    plt.ylabel("False Positive Rate")
    plt.title("False Positive Rate vs Anomalous Traffic Ratio")
    plt.ylim(0.0, 1.05)
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 5))
    plt.plot(anomaly_ratios, entropy_delay, marker="o", label="Entropy-style")
    plt.plot(anomaly_ratios, bucket_delay, marker="s", label="Bucket-dominance")
    plt.xlabel("Anomalous Traffic Ratio")
    plt.ylabel("Average Detection Delay (ms)")
    plt.title("Average Delay vs Anomalous Traffic Ratio")
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

def plot_threshold_sweep():
    thresholds = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]
    accs = []
    fprs = []
    delays = []

    dataset = generate_dataset(num_windows=300, anomaly_ratio=0.5, num_packets=200)

    for th in thresholds:
        metrics = evaluate_method(dataset, "bucket", threshold=th)
        accs.append(metrics["accuracy"])
        fprs.append(metrics["false_positive_rate"])
        delays.append(metrics["avg_delay_ms"])

    plt.figure(figsize=(8, 5))
    plt.plot(thresholds, accs, marker="o", label="Accuracy")
    plt.plot(thresholds, fprs, marker="s", label="False Positive Rate")
    plt.xlabel("Threshold")
    plt.ylabel("Metric Value")
    plt.title("Threshold Tuning for Bucket-Dominance Detector")
    plt.ylim(0.0, 1.05)
    plt.grid(True)
    plt.legend()
    plt.tight_layout()
    plt.show()

    plt.figure(figsize=(8, 5))
    plt.plot(thresholds, delays, marker="o")
    plt.xlabel("Threshold")
    plt.ylabel("Average Delay (ms)")
    plt.title("Detection Delay vs Threshold")
    plt.grid(True)
    plt.tight_layout()
    plt.show()

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------
if __name__ == "__main__":
    plot_window_threshold_behavior(num_windows=40, num_packets=200, threshold=0.35)
    plot_distribution_histogram(num_samples=100, num_packets=200, threshold=0.35)
    plot_metrics_vs_anomaly_ratio()
    plot_threshold_sweep()