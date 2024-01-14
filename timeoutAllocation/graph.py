import matplotlib.pyplot as plt
import numpy as np

# Data for the graphs
algorithms = ['Our Algorithm', 'TSMM', 'AFTM', 'Fixed Timeout' ]
table_sizes = [200, 300]

# Rejected flows
rejected_flows = [[16, 6137, 0, 3621], [0,0, 0, 0]]


# Packet_in_count
packet_in_count = [[31513, 6020, 54147, 47660], [3472, 2716, 54386,49074]]

# Miss rate
miss_rate = [[0.0077, 0.003, 0.013, 0.012], [0.0008, 0.00066, 0.0132, 0.012]]

# CPU usage
cpu_usage = [[0.303, 0.07, 0.314, 0.314], [0.214, 0.084, 0.320, 0.314]]

# Memory usage
memory_usage = [[0.329, 0.09, 0.350, 0.348], [0.263, 0.113, 0.356, 0.354]]

# Average table occupancy
avg_table_occupancy = [[0.757, 0.25, 0.786, 0.916], [0.550, 0.244, 0.524, 0.621]]

# Function to create individual graphs
# Function to create individual graphs
def create_graph(data, title, ylabel):
    fig, ax = plt.subplots()
    bar_width = 0.15
    opacity = 0.8

    # Positions of the bar groups on the x-axis
    index = np.arange(len(table_sizes))

    for i, algorithm in enumerate(algorithms):
        values = [data[0][i], data[1][i]]  # Extracting data for each algorithm
        rects = ax.bar(index + bar_width*i, values, bar_width, alpha=opacity, label=algorithm)

        # Adding data labels
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', va='bottom')

    ax.set_xlabel('Flow Table Size')
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.set_xticks(index + bar_width * len(algorithms) / 2 - bar_width / 2)
    ax.set_xticklabels(table_sizes)
    ax.legend()

    plt.tight_layout()
    plt.show()

# Creating individual graphs for each metric
create_graph(rejected_flows, 'Rejected Flows', 'Number of Flows')
create_graph(packet_in_count, 'Packet In Count', 'Count')
create_graph(miss_rate, 'Miss Rate', 'Rate')
create_graph(cpu_usage, 'CPU Usage', 'Percentage')
create_graph(memory_usage, 'Memory Usage', 'Percentage')
create_graph(avg_table_occupancy, 'Average Table Occupancy', 'Occupancy Ratio')


