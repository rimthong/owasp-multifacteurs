Demo OWASP multifacteurs
======================
Cette route express contient la plupart du code nécéssaire pour notre présentation sur l'authentification avec Google Authenticator et la Yubikey. Ce fichier est en literate coffee-script, ce qui veut dire qu'il peut être parsé comme du MarkDown pour le lire et qu'il est aussi exécutable pour coffeescript. Il suffit donc d'éditer ce fichier et de le compiler en javascript.

Dépendances
---------
Afin de communiquer avec le serveur de Yubico, on a besoin d'**http ou https**. Nous utilisons aussi la librairire **CrypoJS**, qui va nous aider avec quelques outils pour le calcul HMAC et le hachage SHA-1. Finalement, nous utiliserons **lodash** pour facilement gérer nos collections d'utilisateurs en mémoire.

    https = require('https')
    Crypto = (require 'cryptojs').Crypto
    _ = require 'lodash'

    module.exports = (app)->

Utilisateurs
-----
Puisqu'on voulait enveler la complexité de la gestion du BD d'utilisateurs pour cette démo, nous sauvegardons nos utilisateurs dans un tableau. Il est possible d'ajouter des utilisateurs dans le tableau (comme nous verrons dans la route d'enregistrement) mais les utilisateurs seron effacés lorsque le serveur express redémarrera. Notons les champs **yubico_identity** et **googleCode**. **yubico_identity** représente la partie statique du code généré par la yubikey alors que **googleCode** contient le secret partagé de GoogleCode en base32. 

      @users = [
        {
          user: "admin"
          password: "password"
          yubico_identity: "ccccccbggtft"
          googleCode: "JBSWY3DPEHPK3PXP"
        },
        {
          user: "schmuck"
          password: "password"
          yubico_identity: "fifjgjgkhcha"
          googleCode: "JBSWY3DPEHPK3PXX"
        }
      ]

Routes
------
Ici nous définissons deux routes simples, l'index et la page d'enregistrement. Il ne s'agit que de page jade (un outil de templating similaire à haml).

      app.get '/', (req, res )->
        res.render 'index', { title: 'Demo OWASP Multifacteurs' }

      app.get '/register', (req, res )->
        res.render 'register', { title: 'Demo OWASP Multifacteurs' }

La route **do_register** laisse un utilisateur s'enregistrer à notre web-app. Bref, on prend les données du formulaire dans le body et on l'ajoute dans un objet **user** de notre collection **users**. Les deux choses à noter sont qu'on génère un nouveau secret base32 pour utiliser avec google autenticator dans **generateBase32Code()** (plus bas) et qu'on extraie l'identité de la yubikey.On passe aussi le code google à notre vue jade afin de générer un code QR pour notre utilisateur.

      app.post '/do_register', (req, res )->
        code = generateBase32Code()
        user =
          user: req.body.user
          password: req.body.password
          yubico_identity: extractYubicoIdentity req.body.yubicode
          googleCode: code
        @users.push user
        res.render 'do_register', { title: 'Demo OWASP Multifacteurs', user:user.user, code:user.googleCode }

La route **verify** est là où la magie se passe! Premièrement, on commence avec l'habituel:

      app.post '/verify', (req, res )->
        user =_.find @users, (user) ->
          user.user  is  req.body.user
        if user && user.password  is  req.body.password

Rendu là, on sait que notre utilisateur existe et qu'il a entré le bon mot de passe. On doit maintenant déterminer si la clé entrée est une yubikey ou bien un code de google authenticator, puis on appelle le bon algo de vérification. Pour différencier les deux, on regarde la taille du code (une clée yubikey sera de 32 à 48 caractères de long). Certains remarqueront qu'on ne valide pas le keyspace avec un regexp, mais la raison est que Yubico utilise un format du nom de **modhex** pour générer des clés. Ce format découle du fait qu'ils utilisent des drivers de clavier pour leur appareil et le mapping des clés selon la locale peut différer. Si on détecte une ybikey, nous vérifions que la partie identité match avec ce qu'on a sauvegardé dans l'utilisateur.

          key = req.body.key
          if 32 <= key.length <= 48
            identity = extractYubicoIdentity key
            if user.yubico_identity  is  identity
              verifyYubicode key , user, res
            else
              res.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: 'Identité inconnue.' }
          else
            otp = computeOTP(user.googleCode)
            if otp is key
              res.render 'authenticated', {title: 'Demo OWASP Multifacteurs' , user: user.user }
            else
              res.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: 'Mauvaise clé.' }
        else
          res.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: 'Mauvais User/Pass' }

Les fonctions sont détaillées ci-bas.

Vérification de la Yubikey
-------------

Premièrement, on extrait l'identité. Puisque le mot de passe variable est toujours de 32 caractères, le reste est l'identité.

    extractYubicoIdentity = (code) ->
      code.slice 0,-32

Voici la pièce de résistance, la vérification de yubikey. Premièrement si vous avez une API KEY, configurez une variable d'environnement **YUBIKEY\_CLIENT** et **YUBIKEY\_SECRET**. Si vous avez une yubikey, il suffit d'aller sur leur site web pour obtenir une clé. Chaque réponse du serveur Yubico est envoyée avec un hash de signature généré avec leur copie du secret partagé pour l'id du client. En vérifiant la signature avec un re-hachage de la réponse, il est possible de garantir l'intégrité du service. Nous générons aussi un **nonce** pour ajouter à notre requête.

    verifyYubicode = (otp, user, response)->
      clientId = process.env['YUBIKEY_CLIENT'] || 1
      secretKey = process.env['YUBIKEY_SECRET']
      #You would probably use a better random here.
      nonce = Crypto.util.bytesToHex Crypto.util.randomBytes 20

      req = https.get "https://api2.yubico.com/wsapi/2.0/verify?id=#{clientId}&otp=#{otp}&nonce=#{nonce}", (res)->
        data = ""
        res.setEncoding('utf8')

        res.on 'data', (chunk) ->
          data = data + chunk

Le serveur répond à notre requête avec quelques lignes, contenant un **hash**, un **status** pour notre OTP, l'**OTP** lui-même et le **nonce** qu'on lui a envoyé. On construit alors un objet un peu plus facile à manipuler et on vérifie les choses suivantes:
+ On s'assure que le status est OK
+ Le nonce renvoyé est le même qu'on a envoyé
+ L'otp renvoyé est le même qu'on a envoyé

Si tout est beau et qu'on n'a pas de **YUBIKEY\_SECRET**, nous avons terminé

        res.on 'end', () ->
          lines = data.split "\n"
          result = {}
          #Create a friendlier object
          for line in lines
            line = line.split "="
            #We trim the end
            result[line[0]] = line[1]?.replace(/^\s+|\s+$/g, '')
          #restore stripped =
          result.h = result.h + "="
          #Check status
          if result.status  is  "OK"
            #Check nonce
            if result.nonce  is  nonce
              #Check same OTP
              if result.otp  is  otp
                #If we haven't changed our clientId we'll skip hashing
                if clientId  is  1 || !secretKey
                    console.log "Warning: No hash configuration"
                    response.render 'authenticated', {title: 'Demo OWASP Multifacteurs' , user: user.user }
                else

Si on a spécifié un secret yubikey, on utilise HMAC-SHA1 avec cette clé pour générer un hash. Important: le message à hacher consiste en la liste des paramètes en **ordre alphabétique** (sauf h), avec leur valeur et séparés par des **&** au lieu d'espaces. Nous utilisons CryptoJS pour nous aider. Le hash calculé devrait être le même que le paramèetre **h**.

                  #Combine all parameters except  hash, in a single string no new line
                  #Separate params with &, then HMAC-SHA1 it using private key
                  message = "nonce=#{result.nonce}&otp=#{result.otp}&sl=#{result.sl}&status=#{result.status}&t=#{result.t}"
                  key = Crypto.util.base64ToBytes secretKey
                  hmac = Crypto.HMAC(Crypto.SHA1, message, key, null)
                  computedHash = Crypto.util.hexToBytes hmac
                  computedHash = Crypto.util.bytesToBase64 computedHash
                  #Compare the hash
                  if result.h  is  computedHash
                    response.render 'authenticated', {title: 'Demo OWASP Multifacteurs' , user: user.user }
                  else
                    response.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: "Yubico a répondu avec un mauvais hash, imposteur?" }
              else
                response.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: "Yubico répondu avec différent OTP, copy paste?" }
            else
              response.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: "Yubico répondu avec un différent nonce, copy-paste?" }
          else
            response.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: "Yubico répond avec le statut: #{result.status}." }
            
        
      req.on 'error', (e)->
        console.log('problem with request: ' + e.message)
        response.render 'fail', {title: 'Demo OWASP Multifacteurs' , reason: 'Identité Yubico inconnue.' }

Si dessous, génération du code OTP et conversion inspirés par le draft TOTP à l'adresse suivante: http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.html
Implémentation JS inspirée de http://blog.tinisles.com/2011/10/google-authenticator-one-time-password-algorithm-in-javascript/
Il s'agit simplement d'une preuve de concept, il serait interessant de faire un refactor et de ressortir le tout dans une librairie javascript.

    generateBase32Code = ()->
      #Granted, you'll want something a little more advanced than this
      base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
      key = ""
      for i in [1..16]
        key += base32chars.charAt Math.floor( Math.random() * (base32chars.length-1) )
      key
      
    dec2hex = (s) ->
      return (if s < 15.5 then '0' else '') + Math.round(s).toString(16)

    hex2dec = (s) ->
      return parseInt s, 16

Petite note sur la Base32: il existe plusieurs versions. Le principe est qu'il s'agit d'un encodage lisible pour les humains, donc certains éléments comme O et 0 sont évités. Dans le cas de google authenticator, il s'agit de l'alphabet complet et 2-3-4-5-6-7. Plus de détails à [RFC3548](http://tools.ietf.org/html/rfc3548#page-6)

    base32tohex = (base32) ->
      base32chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
      bits = ""
      hex = ""

      for char, index in base32.split ''
        val = base32chars.indexOf(char.toUpperCase())
        bits += leftpad(val.toString(2), 5, '0')

      for char, index in bits.split ''
        if index%4 is 0 && index < bits.length - 1
          chunk = bits.substr(index, 4)
          hex = hex + parseInt(chunk, 2).toString(16)
      hex

    leftpad = (str, len, pad) ->
      if (len + 1 >= str.length)
        str = Array(len + 1 - str.length).join(pad) + str
      str

Finalement, le calcul TOTP utilisé pour Google Authenticator selon [RFC6238](http://tools.ietf.org/html/rfc6238) étant une extension de HOTP défini dans [RFC4226](http://tools.ietf.org/html/rfc4226). 

    computeOTP = (key)->
      delay = 30
      key = base32tohex key
      seconds = Math.round(new Date().getTime() / 1000.0)
      time = leftpad(dec2hex(Math.floor(seconds / delay)), 16, '0')
      bytesTime = Crypto.util.hexToBytes time
      bytesKey = Crypto.util.hexToBytes key
      hmac = Crypto.HMAC(Crypto.SHA1, bytesTime, bytesKey, null)
      offset = hex2dec(hmac.slice -1)
      otp = (hex2dec(hmac.substr(offset * 2, 8)) & hex2dec('7fffffff')) + ''
      otp = otp.slice -6
      otp
