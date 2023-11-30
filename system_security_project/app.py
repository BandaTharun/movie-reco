import rsa
import cryptography
from cryptography.fernet import Fernet
from flask import Flask, render_template, request
from rsa import PublicKey


app = Flask(__name__)


# Generating the encryption key and saving it to a file
def generate_key_S():
    key = Fernet.generate_key()
    with open("Secret.key", "wb") as key_file:
        key_file.write(key)
        
        
def generate_key_A():
    publickey, privatekey = rsa.newkeys(512)

    with open('public.pem', 'wb') as f:
        f.write(publickey.save_pkcs1())

    with open('private.pem', 'wb') as f:
        f.write(privatekey.save_pkcs1())


# Loading the encryption key from the file
def load_key_S():
    return open("Secret.key", "rb").read()


def load_key_A():
    with open('public.pem', 'rb') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())
    
    with open('private.pem', 'rb') as f:
        private_key = rsa.PrivateKey.load_pkcs1(f.read())
    return public_key, private_key



@app.route('/generate_key_S', methods=['POST'])
def generate_and_display_key_S():
    generate_key_S()
    g = load_key_S().decode('utf-8')  # Decode the key to remove 'b' prefix
    return render_template('symmentric.html', output=g)


@app.route('/generate_key_A', methods=['POST'])
def generate_and_display_key_A():
    generate_key_A()
    public_key_data,private_key_data = load_key_A() 
    return render_template('Asymmentric.html', public_key=public_key_data, private_key=private_key_data)



@app.route('/Encrypt_Decrypt_S', methods=['GET', 'POST'])
def encrypt_decrypt_S():
    output_text = ""

    if request.method == 'POST':
        choice = request.form.get('action')
        input_text = request.form.get('input_text')
        key = request.form.get('secret_key')

        try:
            key = key.encode('utf-8')  # Ensure the key is bytes
            f = Fernet(key)            # Create a Fernet object with the key
        except Exception as e:
            return render_template('symmentric.html', output_text=f"Key error: {e}")

        if input_text.strip() == "":
            output_text = "No input is given."
        elif choice == 'Encrypt':
            output_text = f.encrypt(input_text.encode()).decode()
        elif choice == 'Decrypt':
            decrypted_data = f.decrypt(input_text.encode())
            output_text = decrypted_data.decode("utf-8")

    return render_template('symmentric.html', output_text=output_text)



@app.route('/encrypt_decrypt_A', methods=['POST'])
def encrypt_decrypt_A():
    output_text = ""
    if request.method == 'POST':
        choice = request.form.get('action')
        input_text = request.form.get('input_text')
        key= request.form.get('key')
        public_key_data,private_key_data = load_key_A()
        en=''
    if input_text.strip() == "":
        output_text = "No input is given."
    elif choice == 'Encrypt':
        # converting the recived with the orgional key and checking if both are same 
        key2_modulus, key2_exponent = eval(key.split('(')[1].split(')')[0])
        key2 = PublicKey(key2_modulus, key2_exponent) 
        
        if  public_key_data.n == key2.n and public_key_data.e == key2.e:
                # encryption 
                global encryption
                encryption= rsa.encrypt(input_text.encode(),public_key_data)
                output_text=encryption
        else:
                output_text='the given Public key is incorrect , check and try again ' 
                
    elif choice == 'Decrypt': 
        #decryption = rsa.decrypt(en,private_key_data).decode()
        #output_text=decryption
        decryption = rsa.decrypt(encryption,private_key_data).decode()
        output_text=decryption
        
        
    return render_template('Asymmentric.html', output_text=output_text)




@app.route('/Asymmetric')
def Asymmentric():
    return render_template('Asymmentric.html')

@app.route('/symmentric')
def symmentric():
    return render_template('symmentric.html')


@app.route('/home', methods=['POST'])
def home1():
    return render_template('home.html')

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000,debug=True)
