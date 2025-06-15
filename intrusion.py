import streamlit as st
import pandas as pd
import numpy as np
import tensorflow as tf
import seaborn as sns
import matplotlib.pyplot as plt
from tensorflow.keras.models import load_model

# Configure styling
sns.set_theme(style="whitegrid")
st.set_page_config(
    page_title="IoT Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load the pre-trained model
@st.cache_resource
def load_intrusion_model():
    return load_model('intrusion_model.h5')

# Define attack type labels
ATTACK_TYPES = {
    0: 'Normal', 1: 'Backdoor', 2: 'DDoS_HTTP', 
    3: 'DDoS_ICMP', 4: 'DDoS_TCP', 5: 'DDoS_UDP',
    6: 'Fingerprinting', 7: 'MITM', 8: 'Password',
    9: 'Port_Scanning', 10: 'Ransomware', 11: 'SQL_injection',
    12: 'Uploading', 13: 'Vulnerability_scanner', 14: 'XSS'
}

# Critical attacks that trigger alerts
CRITICAL_ATTACKS = {
    'DDoS_HTTP', 'DDoS_ICMP', 'DDoS_TCP', 'DDoS_UDP', 
    'Ransomware', 'SQL_injection', 'Port_Scanning'
}

# Create the Streamlit app
def main():
    # Sidebar with model information
    st.sidebar.header("About")
    st.sidebar.markdown("""
    **IoT Intrusion Detection Dashboard**  
    This system detects and classifies cyber attacks on IoT networks using deep learning.  
    The model achieves 93.6% accuracy on validation data.
    """)
    
    st.sidebar.subheader("Attack Types")
    for code, name in ATTACK_TYPES.items():
        st.sidebar.caption(f"{code}: {name}")
    
    st.sidebar.subheader("Attack Severity")
    st.sidebar.markdown("""
    - 🔴 **Critical**: DDoS, Ransomware, SQL Injection
    - 🟠 **High**: Port Scanning, Backdoor
    - 🟢 **Medium**: Other attacks
    - ⚪ **Normal**: Benign traffic
    """)
    
    st.sidebar.divider()
    st.sidebar.info("﹫2025")
    st.sidebar.download_button(
        label="Download Sample CSV",
        data=pd.DataFrame(columns=range(1, 250)).to_csv(index=False),
        file_name="sample_features.csv",
        mime="text/csv"
    )
    
    # Main content
    st.title("🛡️ Edge IoT Intrusion Detection System")
    st.caption("Detect and classify security threats in IoT network traffic")
    
    # Initialize session state
    if 'predictions' not in st.session_state:
        st.session_state.predictions = None
    if 'critical_alerts' not in st.session_state:
        st.session_state.critical_alerts = []
    
    # Load model
    try:
        model = load_intrusion_model()
    except Exception as e:
        st.error(f"Error loading model: {str(e)}")
        st.stop()
        
    # Alert banner area at top
    alert_placeholder = st.empty()
    
    # Prediction section
    tab1, tab2 = st.tabs(["📊 Batch Prediction", "🔍 Single Prediction"])
    
    with tab1:
        st.subheader("Batch Prediction from CSV")
        uploaded_file = st.file_uploader("Upload IoT device data (CSV)", type="csv")
        
        if uploaded_file:
            try:
                df = pd.read_csv(uploaded_file)
                st.success(f"Successfully loaded {len(df)} records")
                
                # Show sample data
                if st.checkbox("Show data preview"):
                    st.dataframe(df.head())
                
                # Validate features
                if len(df.columns) != 249:
                    st.warning(f"Data should have 249 features. Found {len(df.columns)} columns.")
                    st.info("Ensure your CSV has exactly 249 columns representing the model features")
                else:
                    # Make predictions
                    if st.button("Run Predictions", type="primary"):
                        with st.spinner("Analyzing network traffic..."):
                            # Preprocess and predict
                            X = df.values.astype('float32')
                            pred_probs = model.predict(X, verbose=0)
                            pred_classes = np.argmax(pred_probs, axis=1)
                            confidence_scores = np.max(pred_probs, axis=1)
                            
                            # Add predictions to dataframe
                            df['Predicted_Attack'] = [ATTACK_TYPES[c] for c in pred_classes]
                            df['Prediction_Confidence'] = confidence_scores
                            
                            # Store in session state
                            st.session_state.predictions = df
                            st.session_state.critical_alerts = df[
                                df['Predicted_Attack'].isin(CRITICAL_ATTACKS)
                            ]
            
            except Exception as e:
                st.error(f"Error processing file: {str(e)}")
        
        # Display results if available
        if st.session_state.predictions is not None:
            df = st.session_state.predictions
            
            # Critical attack alert
            if not st.session_state.critical_alerts.empty:
                critical_count = len(st.session_state.critical_alerts)
                with alert_placeholder.container():
                    st.error(f"🚨 **CRITICAL THREAT DETECTED!** - {critical_count} critical attacks identified", 
                            icon="⚠️")
            
            st.subheader("Prediction Results")
            
            # Summary stats
            normal_count = len(df[df['Predicted_Attack'] == 'Normal'])
            attack_count = len(df) - normal_count
            critical_count = len(st.session_state.critical_alerts)
            
            col1, col2, col3 = st.columns(3)
            col1.metric("Total Records", len(df))
            col2.metric("Attack Traffic", f"{attack_count} ({attack_count/len(df):.1%})")
            col3.metric("Critical Threats", critical_count, 
                        f"{critical_count/attack_count:.1%}" if attack_count else "0%")
            
            # Visualization section
            st.subheader("Attack Analysis")
            
            # Tabs for different visualizations
            viz_tab1, viz_tab2, viz_tab3, viz_tab4 = st.tabs([
                "Attack Distribution", 
                "Confidence Analysis",
                "Threat Severity",
                "Detailed Results"
            ])
            
            with viz_tab1:
                col1, col2 = st.columns([3, 2])
                
                with col1:
                    # Attack type bar chart
                    st.markdown("**Attack Type Distribution**")
                    attack_counts = df['Predicted_Attack'].value_counts()
                    fig, ax = plt.subplots(figsize=(10, 6))
                    sns.barplot(
                        x=attack_counts.values, 
                        y=attack_counts.index,
                        palette="viridis",
                        ax=ax
                    )
                    plt.xlabel("Count")
                    plt.ylabel("Attack Type")
                    plt.title("Attack Frequency Distribution")
                    st.pyplot(fig)
                
                with col2:
                    # Attack type pie chart
                    st.markdown("**Attack Proportion**")
                    normal_attack = df['Predicted_Attack'] != 'Normal'
                    attack_ratio = normal_attack.value_counts(normalize=True)
                    
                    fig, ax = plt.subplots(figsize=(8, 6))
                    attack_ratio.plot.pie(
                        autopct='%1.1f%%',
                        labels=['Normal', 'Attack'],
                        colors=['#2ca02c', '#d62728'],
                        startangle=90,
                        ax=ax
                    )
                    plt.title("Normal vs Attack Traffic")
                    plt.ylabel("")
                    st.pyplot(fig)
            
            with viz_tab2:
                col1, col2 = st.columns(2)
                
                with col1:
                    # Confidence histogram
                    st.markdown("**Confidence Distribution**")
                    fig, ax = plt.subplots(figsize=(10, 6))
                    sns.histplot(
                        df['Prediction_Confidence'], 
                        bins=20,
                        kde=True,
                        color='#1f77b4',
                        ax=ax
                    )
                    plt.axvline(x=0.9, color='r', linestyle='--', label='High Confidence')
                    plt.xlabel("Confidence Score")
                    plt.ylabel("Frequency")
                    plt.title("Prediction Confidence Distribution")
                    plt.legend()
                    st.pyplot(fig)
                
                with col2:
                    # Confidence by attack type
                    st.markdown("**Confidence by Attack Type**")
                    fig, ax = plt.subplots(figsize=(10, 6))
                    sns.boxplot(
                        x=df['Prediction_Confidence'],
                        y=df['Predicted_Attack'],
                        palette="Set3",
                        ax=ax
                    )
                    plt.xlabel("Confidence Score")
                    plt.ylabel("Attack Type")
                    plt.title("Confidence Distribution per Attack Type")
                    st.pyplot(fig)
            
            with viz_tab3:
                # Define severity levels
                severity_map = {
                    'Normal': 'Normal',
                    'DDoS_HTTP': 'Critical',
                    'DDoS_ICMP': 'Critical',
                    'DDoS_TCP': 'Critical',
                    'DDoS_UDP': 'Critical',
                    'Ransomware': 'Critical',
                    'SQL_injection': 'Critical',
                    'Port_Scanning': 'High',
                    'Backdoor': 'High',
                    'Fingerprinting': 'Medium',
                    'MITM': 'Medium',
                    'Password': 'Medium',
                    'Uploading': 'Medium',
                    'Vulnerability_scanner': 'Medium',
                    'XSS': 'Medium'
                }
                
                df['Severity'] = df['Predicted_Attack'].map(severity_map)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    # Severity pie chart
                    st.markdown("**Threat Severity Distribution**")
                    severity_counts = df['Severity'].value_counts()
                    
                    fig, ax = plt.subplots(figsize=(8, 8))
                    colors = {'Critical': '#d62728', 'High': '#ff7f0e', 
                                'Medium': '#e377c2', 'Normal': '#2ca02c'}
                    severity_counts.plot.pie(
                        autopct='%1.1f%%',
                        colors=[colors[s] for s in severity_counts.index],
                        startangle=90,
                        ax=ax
                    )
                    plt.title("Threat Severity Levels")
                    plt.ylabel("")
                    st.pyplot(fig)
                
                with col2:
                    # Severity count plot
                    st.markdown("**Threat Severity Counts**")
                    fig, ax = plt.subplots(figsize=(10, 6))
                    sns.countplot(
                        x=df['Severity'],
                        order=['Critical', 'High', 'Medium', 'Normal'],
                        palette=list(colors.values()),
                        ax=ax
                    )
                    plt.xlabel("Severity Level")
                    plt.ylabel("Count")
                    plt.title("Threat Severity Distribution")
                    st.pyplot(fig)
            
            with viz_tab4:
                # Detailed results table
                st.dataframe(df[['Predicted_Attack', 'Prediction_Confidence', 'Severity']].head(50))
            
            # Download results
            st.divider()
            csv = df.to_csv(index=False)
            st.download_button(
                label="Download Full Predictions",
                data=csv,
                file_name="intrusion_predictions.csv",
                mime="text/csv",
                type="primary"
            )
    
    with tab2:
        st.subheader("Single Prediction")
        st.markdown("Enter feature values manually for real-time threat detection")
        
        # Create input form
        with st.form("single_prediction"):
            # Generate sample input features
            sample_features = [0.0] * 249
            inputs = []
            
            st.info("For demonstration, only the first 10 features are shown. Others are set to default values.")
            
            # Split into 3 columns for better layout
            col1, col2, col3 = st.columns(3)
            cols = [col1, col2, col3]
            
            # Only show first 10 features to save space
            features_to_show = 10
            
            for i in range(features_to_show):
                with cols[i % 3]:
                    inputs.append(
                        st.number_input(
                            f"Feature {i+1}",
                            value=sample_features[i],
                            key=f"feature_{i}",
                            step=0.001
                        )
                    )
            
            # Fill remaining features with default values
            inputs += sample_features[features_to_show:]
            
            submit = st.form_submit_button("Analyze Traffic", type="primary")
        
        if submit:
            try:
                # Prepare input data
                input_array = np.array([inputs], dtype='float32')
                
                # Make prediction
                pred_prob = model.predict(input_array, verbose=0)
                pred_class = np.argmax(pred_prob, axis=1)[0]
                confidence = np.max(pred_prob)
                attack_name = ATTACK_TYPES[pred_class]
                
                # Check if critical
                is_critical = attack_name in CRITICAL_ATTACKS
                
                # Display alert
                if is_critical:
                    with alert_placeholder.container():
                        st.error(f"🚨 **CRITICAL THREAT DETECTED!** - {attack_name} attack identified", 
                                icon="⚠️")
                
                # Display results
                st.subheader("Analysis Result")
                
                # Create columns for results
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    # Attack type card
                    severity = "Critical" if is_critical else "Normal" if attack_name == "Normal" else "Warning"
                    color = "#d62728" if is_critical else "#2ca02c" if attack_name == "Normal" else "#ff7f0e"
                    
                    st.markdown(f"""
                    <div style="
                        border: 1px solid {color};
                        border-radius: 10px;
                        padding: 20px;
                        text-align: center;
                        background-color: #f0f2f6;
                        margin-bottom: 20px;
                    ">
                        <h3 style="color: {color}; margin-top: 0;">{attack_name}</h3>
                        <p style="font-size: 18px; margin-bottom: 5px;">Threat Level: <strong>{severity}</strong></p>
                        <p style="font-size: 18px;">Confidence: <strong>{confidence:.2%}</strong></p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    # Confidence indicator
                    st.metric("Prediction Confidence", f"{confidence:.2%}")
                    st.progress(float(confidence))
                
                with col2:
                    # Probability distribution
                    prob_df = pd.DataFrame({
                        'Attack Type': list(ATTACK_TYPES.values()),
                        'Probability': pred_prob[0]
                    }).sort_values('Probability', ascending=False)
                    
                    # Top 10 probabilities
                    top_probs = prob_df.head(10)
                    
                    fig, ax = plt.subplots(figsize=(10, 6))
                    sns.barplot(
                        x='Probability', 
                        y='Attack Type', 
                        data=top_probs,
                        palette="rocket",
                        ax=ax
                    )
                    plt.title("Top 10 Predicted Attack Probabilities")
                    plt.xlabel("Probability")
                    plt.ylabel("")
                    st.pyplot(fig)
                
                # Show full probability table
                with st.expander("View Complete Probability Distribution"):
                    prob_df['Probability'] = prob_df['Probability'].apply(lambda x: f"{x:.4f}")
                    st.dataframe(prob_df)
                
            except Exception as e:
                st.error(f"Prediction error: {str(e)}")
    
    # Add footer
    st.divider()
    st.caption("IoT Security Dashboard v1.0 | Real-time Threat Detection System")

if __name__ == "__main__":
    main()