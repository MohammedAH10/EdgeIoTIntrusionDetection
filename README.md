# Network Intrusion Detection Dashboard

This project provides a Streamlit-based dashboard for real-time network intrusion detection and historical attack visualization.

## Project Structure

```
IDSProject/
├── app.py
├── requirements.txt
├── models/
│   └── best_type_model.keras
├── data/
│   └── Edge-IIoTset/
│       └── train.csv
└── README.md
```

## Setup and Running the Dashboard

1.  **Clone the repository (if not already done):**
    ```bash
    git clone <your-repository-url>
    cd IDSProject
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Place your trained model:**
    Ensure your Keras model file `best_type_model.keras` is placed in the `models/` directory. If it's in the root directory, it will also be found.

5.  **Place your training data (for preprocessor fitting):**
    The dashboard expects a `train.csv` file from your original dataset to fit the data preprocessor. Place it in `data/Edge-IIoTset/train.csv`.

6.  **Run the Streamlit app:**
    ```bash
    streamlit run app.py
    ```

    This will open the dashboard in your web browser.

## Dashboard Features

*   **Real-time Attack Prediction:**
    *   **Upload CSV File:** Upload a CSV file containing network traffic data to get predictions on potential intrusion attacks.
    *   **Manual Feature Input:** Enter individual network traffic feature values manually to test the model on a single instance.
*   **Attack Statistics:**
    *   **Attack Type Distribution:** Visualizes the distribution of different attack types from historical data (currently uses dummy data, replace with your actual historical logs).
    *   **Attacks Over Time:** Shows the trend of attacks over a period (currently uses dummy data).
    *   **World Map (Placeholder):** A section for visualizing geographical attack origins. This requires actual geo-located IP data to be implemented.

## Model and Preprocessing

The dashboard loads a deep learning model (`best_type_model.keras`) trained to predict intrusion attack types. The data preprocessing pipeline (RobustScaler, MinMaxScaler, OneHotEncoder) used during the model training is recreated and applied to new input data to ensure consistent predictions.

## Customization

*   **Historical Data:** Replace the dummy historical data generation in `app.py` with actual attack logs to get meaningful statistics.
*   **World Map:** Integrate a mapping library (e.g., `folium`, `pydeck`) and use geo-located IP data to visualize attack origins on a world map.
*   **UI/UX:** Modify the Streamlit UI elements and styling in `app.py` to further match your desired aesthetic. 