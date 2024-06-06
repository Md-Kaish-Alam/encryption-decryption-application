import base64
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.core.window import Window
from kivy.uix.popup import Popup

# Import Config module
from kivy.config import Config

# set the keyboard mode
Config.set('kivy', 'keyboard_mode', 'systemanddock')


class EncryptionDecryptionApp(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.orientation = "vertical"
        self.padding = (20, 20)
        self.spacing = 10

        # Label for instructions
        self.info_label = Label(
            text="Enter text for encryption and decryption:")
        self.add_widget(self.info_label)

        # Text box for input
        self.text_input = TextInput(multiline=True, font_size=20)
        self.add_widget(self.text_input)

        # Label for password
        self.password_label = Label(
            text="Enter secret key for encryption and decryption:")
        self.add_widget(self.password_label)

        # Password entry field
        self.password_input = TextInput(password=True, font_size=25)
        self.add_widget(self.password_input)

        # Button layout
        self.button_box = BoxLayout(orientation="horizontal")
        self.add_widget(self.button_box)

        # Encrypt button
        self.encrypt_button = Button(text="ENCRYPT", background_color=(0.87, 0.21, 0.21, 1),
                                     font_size=12, color=(1, 1, 1, 1))
        self.encrypt_button.bind(on_press=self.encrypt_text)
        self.button_box.add_widget(self.encrypt_button)

        # Decrypt button
        self.decrypt_button = Button(text="DECRYPT", background_color=(0, 0.73, 0.35, 1),
                                     font_size=12, color=(1, 1, 1, 1))
        self.decrypt_button.bind(on_press=self.decrypt_text)
        self.button_box.add_widget(self.decrypt_button)

        # Reset button
        self.reset_button = Button(text="RESET", background_color=(0.07, 0.55, 0.98, 1),
                                   font_size=12, color=(1, 1, 1, 1))
        self.reset_button.bind(on_press=self.reset_fields)
        self.add_widget(self.reset_button)

    def encrypt_text(self, instance):
        password = self.password_input.text
        text = self.text_input.text

        if password == "1234":
            try:
                encoded_message = base64.b64encode(
                    text.encode("ascii")).decode("ascii")
                self.text_input.text = encoded_message
            except Exception as e:
                self.show_error_message(f"Encryption Error: {str(e)}")
        else:
            self.show_error_message("Invalid Password")

    def decrypt_text(self, instance):
        password = self.password_input.text
        text = self.text_input.text

        if password == "1234":
            try:
                decoded_message = base64.b64decode(
                    text.encode("ascii")).decode("ascii")
                self.text_input.text = decoded_message
            except Exception as e:
                self.show_error_message(f"Decryption Error: {str(e)}")
        else:
            self.show_error_message("Invalid Password")

    def reset_fields(self, instance):
        self.password_input.text = ""
        self.text_input.text = ""

    def show_error_message(self, message):
        popup = Popup(title="Error", content=Label(text=message),
                      size_hint=(None, None), size=(400, 200))
        popup.open()


class EncryptionDecryptionAppWindow(App):
    def build(self):
        Window.size = (400, 400)
        return EncryptionDecryptionApp()


if __name__ == "__main__":
    EncryptionDecryptionAppWindow().run()

