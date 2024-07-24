require "ruby_certisign_login/version"
require 'ruby_certisign_login/engine' 
require 'ruby_certisign_login/helpers/certisign_form_helper' 

module RubyCertisignLogin

  class Decrypt
    # CHAVE criada no site da CertiSignLogin
    CERTISIGN_KEYPATH = File.join( Dir.getwd, "config", "keys", "certisign.pk" )
    #CERTISIGN_KEYPATH = "/var/www/config/keys/certisign.pk"
    #system("echo  #{CERTISIGN_KEYPATH} > /tmp/chave")
    # string: valor recebido como valor da chave 'cb' da requisição de certificado ( params['cb'] )
    def self.new(string)
      # Recusar erros padrões como certificado nao encontado
      return string if string.size < 128
      valid_key?
      # Instanciar e configurar algoritmo
      decipher = OpenSSL::Cipher::AES.new(128, :CBC)
      decipher.decrypt
      decipher.key = File.read(CERTISIGN_KEYPATH).slice(0,16)
      #decipher.iv = 16

      string_decoded = Base64.decode64( string.gsub("certplus", "\\\\+") )
      #
      begin
        decrypt = decipher.update(string_decoded) + decipher.final
      rescue
        # tenta com 256 bits
        decipher = OpenSSL::Cipher::AES.new(256, :CFB)
        decipher.decrypt
        decipher.key = File.read(CERTISIGN_KEYPATH).slice(0,32)
        decrypt = decipher.update(string_decoded) + decipher.final
      end

      eval decrypt.slice( decrypt.index('{'), 999999)
    end

    def self.valid_key?
      unless File.exist? CERTISIGN_KEYPATH
        raise "Adicione sua chave em #{CERTISIGN_KEYPATH}"
      end
    end
  end

  def self.cert_valid?(hash)
    hash[:valido] and hash[:validade].to_date >= Date.today
  end

end
