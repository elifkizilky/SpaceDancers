import matplotlib.pyplot as plt
import numpy as np

# Data for the graphs
algorithms = ['TSMM', 'AFTM', 'Our Algorithm']
table_sizes = [150, 300]

# Rejected flows
rejected_flows = [[963, 0, 152], [0, 0, 0]]

# Hit rate
hit_rate = [[0.982, 0.93, 0.977], [0.979, 0.955, 0.973]]

# Packet_in_count
packet_in_count = [[19060, 75752, 25259], [23236, 49374, 29925]]

# Miss rate
miss_rate = [[0.017, 0.068, 0.022], [0.0208, 0.0445, 0.0267]]

# CPU usage
cpu_usage = [[0.067, 0.24, 0.14], [0.133, 0.232, 0.152]]

# Memory usage
memory_usage = [[0.26, 0.79, 0.55], [0.495, 0.792, 0.572]]

# Average table occupancy
avg_table_occupancy = [[0.23, 0.59, 0.50], [0.225, 0.306, 0.260]]

# Function to create individual graphs
def create_graph(data, title, ylabel):
    fig, ax = plt.subplots()
    bar_width = 0.25
    opacity = 0.8

    # Positions of the bar groups on the x-axis
    index = np.arange(len(table_sizes))

    for i, algorithm in enumerate(algorithms):
        values = [data[0][i], data[1][i]]  # Extracting data for each algorithm
        ax.bar(index + bar_width*i, values, bar_width, alpha=opacity, label=algorithm)

    ax.set_xlabel('Flow Table Size')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(index + bar_width)
    ax.set_xticklabels(table_sizes)
    ax.legend()

    plt.tight_layout()
    plt.show()

# Creating individual graphs for each metric
create_graph(rejected_flows, 'Rejected Flows', 'Number of Flows')
create_graph(hit_rate, 'Hit Rate', 'Rate')
create_graph(packet_in_count, 'Packet In Count', 'Count')
create_graph(miss_rate, 'Miss Rate', 'Rate')
create_graph(cpu_usage, 'CPU Usage', 'Percentage')
create_graph(memory_usage, 'Memory Usage', 'Percentage')
create_graph(avg_table_occupancy, 'Average Table Occupancy', 'Occupancy Ratio')
