import secrets
import string
import hashlib
import piexif
from tkinter import Tk, Label, Button, Entry, filedialog, Text
from PIL import Image

def generate_password(length=16):
    alphabet = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(secrets.choice(alphabet) for _ in range(length))
    return password

def hash_password(password):
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password

def store_hashed_password_in_image(image_path, hashed_password, output_path):
    # Open the image
    img = Image.open(image_path)
    
    # Convert to RGB if the image is in RGBA mode
    if img.mode == 'RGBA':
        img = img.convert('RGB')
    
    # Load existing EXIF data or create a new EXIF data structure
    if 'exif' in img.info:
        exif_dict = piexif.load(img.info['exif'])
    else:
        exif_dict = {
            "0th": {},
            "Exif": {},
            "GPS": {},
            "Interop": {},
            "1st": {},
            "thumbnail": None
        }

    # Set the UserComment tag with hashed password
    exif_dict['Exif'][piexif.ExifIFD.UserComment] = hashed_password.encode('utf-8')

    # Convert EXIF data to bytes
    exif_bytes = piexif.dump(exif_dict)
    
    # Save the image with new EXIF data
    img.save(output_path, exif=exif_bytes)
    
    output_text.insert('end', f"Hashed password stored in the image metadata at {output_path}\n")

def generate_password_gui():
    password_length = int(password_length_entry.get())
    password = generate_password(password_length)
    hashed_password = hash_password(password)
    
    generated_password_text.delete('1.0', 'end')
    generated_password_text.insert('end', f"Generated Password: {password}\nHashed Password: {hashed_password}\n")

def store_password_hash_gui():
    image_path = filedialog.askopenfilename(title="Select an image", filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])
    if image_path:
        output_path = filedialog.asksaveasfilename(defaultextension=".jpg", title="Save Image", filetypes=[("JPEG", "*.jpg"), ("PNG", "*.png")])
        if output_path:
            hashed_password = generated_password_text.get('2.15', '2.end').strip()
            store_hashed_password_in_image(image_path, hashed_password, output_path)

# Setting up the GUI
root = Tk()
root.title("Secure Password Generator & Image Metadata Hasher")

# Password Generation Section
Label(root, text="Generate a Secure Password").pack(pady=10)

Label(root, text="Password Length:").pack()
password_length_entry = Entry(root)
password_length_entry.pack()
password_length_entry.insert(0, "16")

Button(root, text="Generate Password", command=generate_password_gui).pack(pady=5)

generated_password_text = Text(root, height=5, width=50)
generated_password_text.pack()

# Image Metadata Hashing Section
Label(root, text="Store Password Hash in Image Metadata").pack(pady=10)

Button(root, text="Upload Image and Store Hash", command=store_password_hash_gui).pack(pady=5)

output_text = Text(root, height=5, width=50)
output_text.pack()

root.mainloop()
