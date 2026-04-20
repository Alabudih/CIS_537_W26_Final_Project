# Import the random module so the program can generate random values
import random

# Import the time module so the program can measure execution delay
import time

# Import Counter so we can count how many times each destination appears
from collections import Counter

# Import math so we can use log2() in the Shannon entropy formula
import math

# Import matplotlib so we can plot graphs
import matplotlib.pyplot as plt

# Fix the random seed so the same random results are produced each time
random.seed(42)

# ------------------------------------------------------------
# Core helpers
# ------------------------------------------------------------

# Define a function to compute Shannon entropy for a list of items
def shannon_entropy(items):
    # Count how many times each unique item appears
    counts = Counter(items)

    # Get total number of items in the list
    total = len(items)

    # Start entropy at 0.0
    entropy = 0.0

    # Loop through each count value in the frequency table
    for c in counts.values():
        # Compute probability of this item
        p = c / total

        # Add the Shannon entropy contribution: -p * log2(p)
        entropy -= p * math.log2(p)

    # Return final entropy value
    return entropy

# Define a function to compute the maximum traffic concentration ratio
def max_ratio(window):
    # Count occurrences of each destination in the traffic window
    counts = Counter(window)

    # Get total number of packets in the window
    total = len(window)

    # Return the largest count divided by the total packet count
    return max(counts.values()) / total

# ------------------------------------------------------------
# Traffic generation
# ------------------------------------------------------------

# Define a function to generate a normal traffic window
def generate_normal_window(num_packets=200, num_dsts=10):
    # Create a list of possible destination IP addresses
    destinations = [f"10.0.0.{i}" for i in range(1, num_dsts + 1)]

    # Generate packets by randomly choosing among normal destinations
    packets = [random.choice(destinations) for _ in range(num_packets)]

    # Return the packet list and label 0 for normal traffic
    return packets, 0  # 0 = normal

# Define a function to generate anomalous traffic
def generate_anomalous_window(num_packets=200, num_dsts=10, hot_prob=0.75):
    # Create a list of possible destination IP addresses
    destinations = [f"10.0.0.{i}" for i in range(1, num_dsts + 1)]

    # Select one destination to behave like a "hot" suspicious target
    hot_dst = "10.0.0.9"

    # Create an empty packet list
    packets = []

    # Loop once for each packet to be generated
    for _ in range(num_packets):
        # With probability hot_prob, send packet to the hot destination
        if random.random() < hot_prob:
            packets.append(hot_dst)
        else:
            # Otherwise choose a normal destination
            packets.append(random.choice(destinations))

    # Return the packet list and label 1 for anomaly
    return packets, 1  # 1 = anomaly

# Define a function to build a full dataset of normal + anomalous windows
def generate_dataset(num_windows=100, anomaly_ratio=0.5, num_packets=200):
    # Create an empty list to store all windows
    data = []

    # Compute how many anomalous windows to create
    num_anom = int(num_windows * anomaly_ratio)

    # Compute how many normal windows to create
    num_norm = num_windows - num_anom

    # Generate all normal windows
    for _ in range(num_norm):
        # Append one normal window to the dataset
        data.append(generate_normal_window(num_packets=num_packets))

    # Generate all anomalous windows
    for _ in range(num_anom):
        # Append one anomalous window to the dataset
        data.append(generate_anomalous_window(num_packets=num_packets))

    # Shuffle the dataset so normal and anomaly samples are mixed
    random.shuffle(data)

    # Return the dataset
    return data

# ------------------------------------------------------------
# Detection methods
# ------------------------------------------------------------

# Define an entropy-based detector
def detect_entropy(window, baseline_entropy, alpha):
    # Compute the entropy of the current traffic window
    current_entropy = shannon_entropy(window)

    # If entropy differs from the baseline by more than alpha, flag anomaly
    return 1 if abs(current_entropy - baseline_entropy) > alpha else 0

# Define a detector based on whether one destination dominates the window
def detect_bucket_dominance(window, threshold=0.35):
    # Compute the maximum destination ratio
    mr = max_ratio(window)

    # If one destination exceeds threshold, flag anomaly
    return 1 if mr > threshold else 0

# ------------------------------------------------------------
# Metrics
# ------------------------------------------------------------

# Define a function to compute evaluation metrics
def compute_metrics(y_true, y_pred, delays_ms):
    # Initialize confusion matrix values
    tp = tn = fp = fn = 0

    # Loop through ground-truth labels and predictions together
    for t, p in zip(y_true, y_pred):
        # True positive: predicted anomaly and it was anomaly
        if p == 1 and t == 1:
            tp += 1
        # True negative: predicted normal and it was normal
        elif p == 0 and t == 0:
            tn += 1
        # False positive: predicted anomaly but it was normal
        elif p == 1 and t == 0:
            fp += 1
        # Otherwise it is a false negative
        else:
            fn += 1

    # Total number of evaluated samples
    total = tp + tn + fp + fn

    # Compute accuracy safely
    accuracy = (tp + tn) / total if total else 0.0

    # Compute false positive rate safely
    fpr = fp / (fp + tn) if (fp + tn) else 0.0

    # Compute false negative rate safely
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    # Compute average delay safely
    avg_delay = sum(delays_ms) / len(delays_ms) if delays_ms else 0.0

    # Return all metrics in a dictionary
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

# Define a function to evaluate one detection method on a dataset
def evaluate_method(dataset, method_name, **kwargs):
    # Store ground-truth labels here
    y_true = []

    # Store predicted labels here
    y_pred = []

    # Store execution delay for each window here
    delays_ms = []

    # Loop through each traffic window and its label
    for window, label in dataset:
        # Record start time before detection
        start = time.perf_counter()

        # If user selected entropy detector
        if method_name == "entropy":
            # Run entropy detector using provided baseline and alpha
            pred = detect_entropy(window, kwargs["baseline_entropy"], kwargs["alpha"])

        # If user selected bucket-dominance detector
        elif method_name == "bucket":
            # Run bucket-dominance detector using provided threshold
            pred = detect_bucket_dominance(window, kwargs["threshold"])

        # If method name is unknown, stop with an error
        else:
            raise ValueError("Unknown method")

        # Record end time after detection
        end = time.perf_counter()

        # Save the true label
        y_true.append(label)

        # Save the predicted label
        y_pred.append(pred)

        # Save the detection delay in milliseconds
        delays_ms.append((end - start) * 1000.0)

    # Return computed performance metrics
    return compute_metrics(y_true, y_pred, delays_ms)

# Define a function to estimate a baseline entropy from normal traffic
def baseline_entropy_from_normal(num_samples=50, num_packets=200):
    # Create a list to store entropy values from normal windows
    entropies = []

    # Generate many normal windows to estimate a stable baseline
    for _ in range(num_samples):
        # Generate one normal traffic window
        window, _ = generate_normal_window(num_packets=num_packets)

        # Compute and store its entropy
        entropies.append(shannon_entropy(window))

    # Return the average entropy of those normal windows
    return sum(entropies) / len(entropies)

# ------------------------------------------------------------
# Refined visualization helpers
# ------------------------------------------------------------

# Define a function to visualize threshold behavior window by window
def plot_window_threshold_behavior(num_windows=40, num_packets=200, threshold=0.35):
    # Store traffic windows
    windows = []

    # Store labels for each window
    labels = []

    # Store max-ratio values for each window
    ratios = []

    # Generate first half as normal traffic
    for _ in range(num_windows // 2):
        # Create one normal window and its label
        w, l = generate_normal_window(num_packets=num_packets)

        # Save the window
        windows.append(w)

        # Save its label
        labels.append(l)

        # Save its max traffic ratio
        ratios.append(max_ratio(w))

    # Generate second half as anomalous traffic
    for _ in range(num_windows // 2):
        # Create one anomalous window and its label
        w, l = generate_anomalous_window(num_packets=num_packets)

        # Save the window
        windows.append(w)

        # Save its label
        labels.append(l)

        # Save its max traffic ratio
        ratios.append(max_ratio(w))

    # Create x-axis indices from 1 to num_windows
    x = list(range(1, num_windows + 1))

    # Create a figure with specific size
    plt.figure(figsize=(10, 5))

    # Plot normal windows in the first half
    plt.plot(x[:num_windows // 2], ratios[:num_windows // 2], marker="o", label="Normal windows")

    # Plot anomalous windows in the second half
    plt.plot(x[num_windows // 2:], ratios[num_windows // 2:], marker="s", label="Anomalous windows")

    # Draw a horizontal line showing the detection threshold
    plt.axhline(y=threshold, linestyle="--", label=f"Threshold = {threshold:.2f}")

    # Label x-axis
    plt.xlabel("Window Index")

    # Label y-axis
    plt.ylabel("Max Traffic Ratio")

    # Set plot title
    plt.title("Threshold Crossing: Normal vs Anomalous Traffic")

    # Add grid lines
    plt.grid(True)

    # Show legend
    plt.legend()

    # Improve spacing
    plt.tight_layout()

    # Display the plot
    plt.show()

# Define a function to plot histograms of traffic concentration
def plot_distribution_histogram(num_samples=100, num_packets=200, threshold=0.35):
    # Store normal max-ratio values
    normal_ratios = []

    # Store anomaly max-ratio values
    anomaly_ratios = []

    # Loop to generate paired normal and anomaly samples
    for _ in range(num_samples):
        # Generate a normal window
        w, _ = generate_normal_window(num_packets=num_packets)

        # Compute and store its max ratio
        normal_ratios.append(max_ratio(w))

        # Generate an anomalous window
        w, _ = generate_anomalous_window(num_packets=num_packets)

        # Compute and store its max ratio
        anomaly_ratios.append(max_ratio(w))

    # Create figure
    plt.figure(figsize=(10, 5))

    # Plot histogram of normal ratios
    plt.hist(normal_ratios, bins=15, alpha=0.7, label="Normal")

    # Plot histogram of anomaly ratios
    plt.hist(anomaly_ratios, bins=15, alpha=0.7, label="Anomalous")

    # Draw threshold line
    plt.axvline(x=threshold, linestyle="--", label=f"Threshold = {threshold:.2f}")

    # Label x-axis
    plt.xlabel("Max Traffic Ratio")

    # Label y-axis
    plt.ylabel("Number of Windows")

    # Set title
    plt.title("Distribution of Traffic Concentration")

    # Add grid
    plt.grid(True)

    # Show legend
    plt.legend()

    # Improve spacing
    plt.tight_layout()

    # Display plot
    plt.show()

# Define a function to compare metrics as anomaly ratio changes
def plot_metrics_vs_anomaly_ratio():
    # Compute baseline entropy from normal traffic
    baseline_entropy = baseline_entropy_from_normal()

    # Define anomaly ratios to test
    anomaly_ratios = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7]

    # Store entropy-based accuracy values
    entropy_acc = []

    # Store bucket-based accuracy values
    bucket_acc = []

    # Store entropy-based delays
    entropy_delay = []

    # Store bucket-based delays
    bucket_delay = []

    # Store entropy-based false positive rates
    entropy_fpr = []

    # Store bucket-based false positive rates
    bucket_fpr = []

    # Loop through each anomaly ratio and evaluate both detectors
    for ratio in anomaly_ratios:
        # Generate a dataset with the current anomaly ratio
        dataset = generate_dataset(num_windows=200, anomaly_ratio=ratio, num_packets=200)

        # Evaluate entropy detector
        entropy_metrics = evaluate_method(
            dataset,
            "entropy",
            baseline_entropy=baseline_entropy,
            alpha=0.60
        )

        # Evaluate bucket-dominance detector
        bucket_metrics = evaluate_method(
            dataset,
            "bucket",
            threshold=0.35
        )

        # Save entropy accuracy
        entropy_acc.append(entropy_metrics["accuracy"])

        # Save bucket accuracy
        bucket_acc.append(bucket_metrics["accuracy"])

        # Save entropy delay
        entropy_delay.append(entropy_metrics["avg_delay_ms"])

        # Save bucket delay
        bucket_delay.append(bucket_metrics["avg_delay_ms"])

        # Save entropy false positive rate
        entropy_fpr.append(entropy_metrics["false_positive_rate"])

        # Save bucket false positive rate
        bucket_fpr.append(bucket_metrics["false_positive_rate"])

        # Print metrics for this anomaly ratio
        print(f"\nAnomaly ratio = {ratio:.1f}")
        print("Entropy-style metrics:", entropy_metrics)
        print("Bucket-style metrics :", bucket_metrics)

    # Plot accuracy comparison
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

    # Plot false positive rate comparison
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

    # Plot delay comparison
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

# Define a function to sweep threshold values for bucket detector
def plot_threshold_sweep():
    # Threshold values to test
    thresholds = [0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]

    # Store accuracy values
    accs = []

    # Store false positive rates
    fprs = []

    # Store delays
    delays = []

    # Generate one fixed dataset for threshold comparison
    dataset = generate_dataset(num_windows=300, anomaly_ratio=0.5, num_packets=200)

    # Loop through each threshold
    for th in thresholds:
        # Evaluate bucket detector using this threshold
        metrics = evaluate_method(dataset, "bucket", threshold=th)

        # Save accuracy
        accs.append(metrics["accuracy"])

        # Save false positive rate
        fprs.append(metrics["false_positive_rate"])

        # Save average delay
        delays.append(metrics["avg_delay_ms"])

    # Plot accuracy and false positive rate
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

    # Plot delay vs threshold
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

# Only run this block when the file is executed directly
if __name__ == "__main__":
    # Plot normal vs anomalous threshold crossing behavior
    plot_window_threshold_behavior(num_windows=40, num_packets=200, threshold=0.35)

    # Plot histograms of normal vs anomalous traffic concentration
    plot_distribution_histogram(num_samples=100, num_packets=200, threshold=0.35)

    # Plot performance metrics as anomaly ratio changes
    plot_metrics_vs_anomaly_ratio()

    # Plot performance as threshold changes
    plot_threshold_sweep()
