import gui_system 

# Now you can use things *from* that module:

import GUIControl
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QGroupBox, QSizePolicy, QLineEdit, QTextEdit
)
# # 1. Import the Class
# from gui_system 
import GUIControlSystem 
# In your main script file:


# 2. Import standard libraries
import time
import random

# --- rest of your code starts here ---
# system = GUIControlSystem() 

import serial # Requires pyserial library

# ==============================================================================
# PART 1: MACHINE LEARNING MODEL (ANN)
# This model is used to predict system behavior (e.g., torque response) 
# which can improve the robustness of the MPC prediction step.
# ==============================================================================

class ANNModel:
    """
    Simple ANN wrapper for system identification. 
    In a real setup, this would use complex training data.
    """
    def __init__(self):
        print("[INFO] Initializing ANN Model (Simulated Training)")
        # Placeholder for actual NN implementation (e.g., using TensorFlow/PyTorch)
        self.is_trained = True
        self.params = {"k_L": 0.9, "k_V": 1.1} # Example learned parameters

    def train(self, training_data):
        """Simulates the training process."""
        print(f"[ANN] Training started with {len(training_data)} data points...")
        # --- ACTUAL TRAINING LOGIC GOES HERE ---
        time.sleep(1) 
        print("[ANN] Model training complete. Parameters updated successfully.")
        self.is_trained = True

    def predict(self, input_state):
        """Predicts the next state (e.g., next current or voltage based on input)."""
        # Example prediction: Next current estimate based on current input and learned parameters
        predicted_current = input_state[0] * self.params["k_L"] + np.sin(input_state[1]) * 0.1
        return max(0, predicted_current) # Ensure non-negative current

# ==============================================================================
# PART 2: CONTROL LOGIC (MPC)
# Implements the Model Predictive Control core.
# ==============================================================================

class MPC_Controller:
    """
    Model Predictive Controller for BLDC.
    The controller minimizes a cost function over a prediction horizon (N).
    """
    def __init__(self, motor_params, ann_model):
        self.P = motor_params['P']
        self.R = motor_params['R']
        self.L = motor_params['L']
        self.ANN = ann_model
        print("[MPC] Controller initialized.")

    def calculate_cost(self, predicted_thrust, u_k):
        """
        The core cost function J: 
        J = sum( (error)^2 + (control_effort)^2 )
        """
        # Error term: minimizes tracking error (e.g., desired RPM vs predicted RPM)
        error_cost = (predicted_thrust - 10)**2 
        # Effort cost: penalizes large voltage/current changes
        effort_cost = u_k[0]**2 + u_k[1]**2
        
        total_cost = error_cost + 0.1 * effort_cost
        return total_cost

    def run_mpc(self, current_state, desired_target):
        """
        Performs the MPC optimization step.
        Finds the optimal sequence of inputs (u_k) over the prediction horizon N.
        """
        N = 5 # Prediction Horizon (how many steps ahead to look)
        
        optimal_u = []
        min_cost = float('inf')
        best_u = None

        # 1. Optimization Loop (Simulated optimization over N steps)
        for iteration in range(1, 10): # Iterating through potential control vectors
            # Simulate generating a control input vector u_k = [V_abc, I_abc]
            u_k_test = np.array([random.uniform(1, 11), random.uniform(1, 11)]) 
            
            # 2. Prediction Step (Using the ANN prediction for robustness)
            predicted_i_next = self.ANN.predict(np.array([current_state['current'], current_state['rpm']]))
            predicted_thrust = 10 + (u_k_test[0] / 10) # Simple prediction
            
            # 3. Calculate Cost
            cost = self.calculate_cost(predicted_thrust, u_k_test)

            if cost < min_cost:
                min_cost = cost
                best_u = u_k_test
        
        # The best_u is the optimal control action for the current step
        return best_u, min_cost

# ==============================================================================
# PART 3: DATA ACQUISITION (SIMULATED USB/COM PORT)
# ==============================================================================

class DataAcquisition:
    """
    Handles the connection and reading of real-time data from a COM port.
    """
    def __init__(self, port='/dev/ttyUSB0', baudrate=9600):
        self.port = port
        self.baudrate = baudrate
        self.serial_connection = None
        print(f"[DAQ] Data Acquisition module ready. Target Port: {port}")

    def connect(self):
        """Attempts to establish serial connection."""
        try:
            # NOTE: Change '/dev/ttyUSB0' to 'COM3' for Windows
            self.serial_connection = serial.Serial(self.port, self.baudrate, timeout=1)
            time.sleep(2) # Wait for connection handshake
            print(f"\n[DAQ] Successfully connected to {self.port}!")
            return True
        except serial.SerialException as e:
            print(f"\n[ERROR] Could not connect to the serial port: {e}")
            print("Running in SIMULATED MODE. Please check your COM port settings.")
            self.serial_connection = None
            return False

    def read_data(self):
        """
        Reads a structured string data packet (e.g., "I,V,RPM\n").
        If serial is unavailable, it returns simulated data.
        """
        if self.serial_connection and self.serial_connection.is_open:
            try:
                line = self.serial_connection.readline().decode('utf-8').strip()
                if line:
                    # Assuming data format: Current, Voltage, RPM
                    i, v, rpm = map(float, line.split(','))
                    return {'current': i, 'voltage': v, 'rpm': rpm}
            except Exception as e:
                print(f"[DAQ Error] Failed to read data: {e}")
                pass
        
        # Fallback: Simulation Mode (Perfect for testing the GUI and MPC logic)
        print("[DAQ] Running in SIMULATED MODE.")
        simulated_data = {
            'current': 0.5 + np.sin(time.time()/5)*0.3,
            'voltage': 12.0 + np.cos(time.time()/10)*0.1,
            'rpm': 1500 + np.sin(time.time()/3)*50
        }
        return simulated_data


# ==============================================================================
# PART 4: GUI SYSTEM (PYQT5)
# ==============================================================================

class GUI_System(QMainWindow):
    def __init__(self, daq_module, mpc_controller):
        super().__init__()
        self.daq = daq_module
        self.mpc = mpc_controller
        self.setWindowTitle("⚡️ BLDC Predictive Control System (MPC + ANN)")
        self.setGeometry(100, 100, 1400, 800)
        self.setup_ui()
        self.setup_plot_axes()

    def setup_ui(self):
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)

        # --- 1. Status Panel (Left Side) ---
        status_group = QGroupBox("Motor Status / Control Inputs")
        status_layout = QVBoxLayout()
        
        # Current Display
        self.lbl_current = QLabel("I: -- A")
        self.lbl_current.setStyleSheet("font-size: 24pt; color: blue;")
        status_layout.addWidget(self.lbl_current)
        
        # Voltage Display
        self.lbl_voltage = QLabel("V: -- V")
        self.lbl_voltage.setStyleSheet("font-size: 24pt; color: green;")
        status_layout.addWidget(self.lbl_voltage)

        # RPM Display
        self.lbl_rpm = QLabel("RPM: --")
        self.lbl_rpm.setStyleSheet("font-size: 24pt; color: orange;")
        status_layout.addWidget(self.lbl_rpm)

        # Control Buttons and Info
        control_layout = QHBoxLayout()
        self.start_btn = QPushButton("▶ Start Control Loop")
        self.start_btn.clicked.connect(self.start_control)
        
        self.train_btn = QPushButton("🧠 Train ANN Model")
        self.train_btn.clicked.connect(self.run_training)
        
        control_layout.addWidget(self.start_btn)
        control_layout.addWidget(self.train_btn)
        status_layout.addLayout(control_layout)
        status_layout.addStretch()
        
        status_group.setLayout(status_layout)
        main_layout.addWidget(status_group, 1) # Takes 1/4 width

        # --- 2. Visualization Panel (Right Side) ---
        viz_group = QGroupBox("System Visualization & Prediction")
        viz_layout = QVBoxLayout()
        
        # Graphs (Stacked Matplotlib Canvas)
        self.plot_canvas = FigureCanvas(plt.figure(figsize=(10, 6)))
        viz_layout.addWidget(self.plot_canvas)
        
        # Serial Output Log
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setText("--- System Log Initialized ---")
        viz_layout.addWidget(QLabel("Communication Log:"))
        viz_layout.addWidget(self.log_output)
        
        viz_group.setLayout(viz_layout)
        main_layout.addWidget(viz_group, 3) # Takes 3/4 width

    def setup_plot_axes(self):
        """Initializes the matplotlib figure with three subplots."""
        fig = plt.figure(figsize=(10, 6))
        self.ax_current = fig.add_subplot(3, 1, 1) # Top plot: Current
        self.ax_voltage = fig.add_subplot(3, 1, 2) # Middle plot: Voltage
        self.ax_rpm = fig.add_subplot(3, 1, 3) # Bottom plot: RPM
        
        # Ensure the matplotlib canvas is associated with this figure
        self.plot_canvas.setParent(self)

    # --- Simulation/Control Methods ---

    def run_simulation_step(self):
        """Simulates one cycle of data acquisition and control action."""
        # 1. Get current data (Simulated or Real)
        current_data = self.get_current_readings()
        
        # 2. Process and Decide (Control Logic)
        # In a real system, this would run PID/MPC control loops
        control_signal = self.calculate_control_signal(current_data)
        
        # 3. Update State (Simulated Write)
        self.simulate_update(control_signal)

        # 4. Display Data
        self.update_plot(current_data)
        self.update_status(control_signal)
        
        print("--- Simulation Step Complete ---")

    def calculate_control_signal(self, data):
        """Placeholder for complex control algorithm."""
        # Example: If speed is too low, command higher voltage
        error = 100 - data['rpm']
        if error > 10:
            return f"High Voltage Command (Error: {error:.1f})"
        return "Nominal Control Signal"

    def update_status(self, signal):
        """Updates a status indicator or console log."""
        print(f"CONTROL ACTION: {signal}")

    def get_current_readings(self):
        """Simulates reading sensor data."""
        import random
        return {
            'rpm': 100 + random.uniform(-10, 10), # Simulate slightly fluctuating speed
            'voltage': 230 + random.uniform(-2, 2)
        }

    def simulate_update(self, signal):
        """Simulates writing a command to the hardware."""
        print(f"HARDWARE OUTPUT: Applying signal: {signal}")

    def update_plot(self, data):
        """Plots the acquired sensor data."""
        # In a real application, use PyQtGraph or matplotlib for plotting
        print(f"\n[SENSOR DATA] RPM: {data['rpm']:.2f} | Voltage: {data['voltage']:.2f}")
        # Actual plotting code would go here

    def update_status(self, signal):
        """Updates the GUI status panel."""
        print(f"STATUS PANEL: {signal}")

# --- Main Execution ---
if __name__ == "__main__":
    # Initialize the simulation object
    system = GUIControlSystem()
    
    print("="*50)
    print("CONTROL SYSTEM SIMULATION STARTED")
    print("="*50)
    
    # Run the simulation loop a few times
    for i in range(3):
        print(f"\n========== RUN CYCLE {i+1} ==========")
        # In a real GUI, this would be connected to a timer event (e.g., every 50ms)
        system.run_simulation_step()
        
    print("\n=====================================")
    print("SIMULATION ENDED")
