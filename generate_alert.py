import numpy as np
from scipy.io import wavfile

def generate_alert_sound():
    # Generate a simple alert sound (beep)
    sample_rate = 44100
    duration = 0.5  # seconds
    frequency = 1000  # Hz
    
    t = np.linspace(0, duration, int(sample_rate * duration), False)
    sound = np.sin(2 * np.pi * frequency * t) * 0.5
    
    # Add a slight fade out
    fade_out = np.linspace(1, 0, len(sound))
    sound = sound * fade_out
    
    # Convert to 16-bit PCM
    sound = (sound * 32767).astype(np.int16)
    
    # Save as WAV file
    wavfile.write('alert.wav', sample_rate, sound)

if __name__ == "__main__":
    generate_alert_sound()
    print("Alert sound generated successfully!") 