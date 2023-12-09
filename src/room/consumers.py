import json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from channels.generic.websocket import AsyncWebsocketConsumer
from asgiref.sync import sync_to_async
from .models import Room, Message
from django.contrib.auth.models import User


class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.room_name = self.scope['url_route']['kwargs']['room_name']
        self.room_group_name = 'chat_%s' % self.room_name

        # Generate and store server's public and private keys
        self.server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        self.server_public_key = self.server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        await self.accept()


    async def disconnect(self):
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        message = data['message']
        username = data['username']
        room = data['room']

        await self.save_message(username, room, message)

        # Encrypt the message using the server's public key
        encrypted_message = self.encrypt_message(message, self.server_public_key)

        # Send encrypted message to room group
        await self.channel_layer.group_send(
            self.room_group_name,
            {
                'type': 'chat_message',
                'message': encrypted_message,
                'username': username
            }
        )

    def encrypt_message(self, message, public_key):
        public_key = serialization.load_pem_public_key(public_key)
        ciphertext = public_key.encrypt(
            message.encode('utf-8'),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext


    # Receive message from room group

    async def chat_message(self, event):
        encrypted_message = event['message']
        username = event['username']

        # Decrypt the message using the server's private key
        decrypted_message = self.decrypt_message(encrypted_message, self.server_private_key)

        # Send decrypted message to WebSocket
        await self.send(text_data=json.dumps({
            'message': decrypted_message,
            'username': username
        }))
    
    def decrypt_message(self, ciphertext, private_key):
        private_key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext.decode('utf-8')


    @sync_to_async
    def save_message(self, username, room, message):
        user = User.objects.get(username=username)
        room = Room.objects.get(slug=room)

        Message.objects.create(user=user, room=room, content=message)

