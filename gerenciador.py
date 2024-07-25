from cryptography.fernet import Fernet
import os
import json

class PasswordManager:
    def __init__(self):
        """
        Inicializa o gerenciador de senhas.
        Carrega a chave de criptografia e as senhas armazenadas (se houver).
        """
        self.passwords = {}  # Dicionário para armazenar pares de site e senha criptografada.
        self.key = None  # Chave de criptografia.
        self.cipher_suite = None  # Objeto para criptografar e descriptografar senhas.
        self.load_key()  # Carrega ou gera a chave de criptografia.
        self.load_passwords()  # Carrega as senhas criptografadas do arquivo.

    def load_key(self):
        """
        Carrega a chave de criptografia de um arquivo ou gera uma nova chave se o arquivo não existir.
        """
        if os.path.exists("secret.key"):
            # Carrega a chave existente do arquivo.
            with open("secret.key", "rb") as key_file:
                self.key = key_file.read()
        else:
            # Gera uma nova chave e a salva no arquivo.
            self.key = Fernet.generate_key()
            with open("secret.key", "wb") as key_file:
                key_file.write(self.key)
        self.cipher_suite = Fernet(self.key)  # Inicializa o objeto de criptografia com a chave.

    def load_passwords(self):
        """
        Carrega as senhas criptografadas do arquivo JSON.
        """
        if os.path.exists("passwords.json"):
            # Carrega o conteúdo do arquivo JSON para o dicionário de senhas.
            with open("passwords.json", "r") as password_file:
                self.passwords = json.load(password_file)

    def save_passwords(self):
        """
        Salva as senhas criptografadas no arquivo JSON.
        """
        with open("passwords.json", "w") as password_file:
            # Salva o dicionário de senhas no arquivo JSON.
            json.dump(self.passwords, password_file)

    def add_password(self, site, password):
        """
        Adiciona uma senha criptografada ao gerenciador de senhas.

        Parameters:
        site (str): O nome do site.
        password (str): A senha a ser armazenada.
        """
        # Criptografa a senha e decodifica para string.
        encrypted_password = self.cipher_suite.encrypt(password.encode()).decode()
        self.passwords[site] = encrypted_password  # Armazena a senha criptografada.
        self.save_passwords()  # Salva as senhas atualizadas no arquivo.
        print(f"Senha do {site} adicionada com sucesso.")

    def get_password(self, site):
        """
        Obtém a senha descriptografada para um site específico.

        Parameters:
        site (str): O nome do site.
        
        Returns:
        str: A senha descriptografada, ou uma mensagem indicando que o site não foi encontrado.
        """
        if site in self.passwords:
            # Descriptografa a senha e a decodifica de volta para string.
            encrypted_password = self.passwords[site].encode()
            decrypted_password = self.cipher_suite.decrypt(encrypted_password).decode()
            return decrypted_password
        else:
            return "Password for site not found."

    def remove_password(self, site):
        """
        Remove a senha armazenada para um site específico.

        Parameters:
        site (str): O nome do site.
        """
        if site in self.passwords:
            del self.passwords[site]  # Remove a senha do dicionário.
            self.save_passwords()  # Salva as senhas atualizadas no arquivo.
            print(f"Senha do {site} removida com sucesso.")
        else:
            print("Senha do site não foi encontrada.")

    def decrypt_all_passwords(self):
        """
        Descriptografa e exibe todas as senhas armazenadas.
        """
        if not self.passwords:
            print("Nenhuma senha armazenada.")
        else:
            # Itera sobre todas as senhas e exibe a senha descriptografada.
            for site, encrypted_password in self.passwords.items():
                decrypted_password = self.cipher_suite.decrypt(encrypted_password.encode()).decode()
                print(f"Site: {site}, Password: {decrypted_password}")

def main():
    """
    Função principal que fornece a interface de linha de comando para o gerenciador de senhas.
    """
    manager = PasswordManager()  # Cria uma instância do gerenciador de senhas.

    while True:
        # Exibe o menu de opções para o usuário.
        print("\nGerenciador de Senhas")
        print("1. Adicionar Senha")
        print("2. Ver Senha")
        print("3. Remover Senhas")
        print("4. Descriptografar todas as senhas")
        print("5. Sair")
        choice = input("Digita sua escolha: ")

        if choice == "1":
            site = input("Digite o site: ")
            password = input("Digite a senha: ")
            manager.add_password(site, password)  # Adiciona a senha ao gerenciador.
        elif choice == "2":
            site = input("Digite o site: ")
            print("Password:", manager.get_password(site))  # Obtém e exibe a senha.
        elif choice == "3":
            site = input("Digite o site: ")
            manager.remove_password(site)  # Remove a senha do gerenciador.
        elif choice == "4":
            manager.decrypt_all_passwords()  # Descriptografa e exibe todas as senhas.
        elif choice == "5":
            break  # Sai do loop e encerra o programa.
        else:
            print("Escolha inválida. Tente novamente")  # Mensagem de erro para opção inválida.

if __name__ == "__main__":
    main()
