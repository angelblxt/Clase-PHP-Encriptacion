<?php

	/**
	*
	* Clase encargada de englobar funciones de encriptación / desencriptación.
	*
	* @author Ángel Querol García <angelquerolgarcia@gmail.com>
	*
	*/

	class Security{

		private $_algorithm;
		private $_mode;

		/**
		*
		* Clase constructora en las que se especifican el algoritmo y modo utilizados.
		*
		*/

			public function __construct()
			{

				$this->_algorithm = 'rijndael-256';
				$this->_mode      = 'ctr';

			}

		/**
		*
		* Método encargado de encriptar una cadena.
		*
		* @param string $string Cadena a encriptar.
		* @param string $key Semilla con la cual encriptar.
		* @param string $secLevel Nivel de seguridad de encriptación (1: Normal, 2: Alto).
		*
		* @return string Cadena encriptada.
		*
		*/

			public function encrypt( $string, $key, $secLevel = 2 )
			{

				if( $secLevel == 1 ){

					$result = '';

					for( $i=0; $i<strlen($string); $i++ ){

						$char       = substr($string, $i, 1);
						$keychar    = substr($key, ($i % strlen($key)) - 1, 1);
						$char       = chr(ord($char)+ord($keychar));
						$result .= $char;
					
					}

					return base64_encode($result);

				} elseif( $secLevel == 2 ){

					if( !$td = mcrypt_module_open($this->_algorithm, '', $this->_mode, '') )
						return false;

					$string = serialize($string);
					$iv     = mcrypt_create_iv(32, MCRYPT_RAND);

					if( mcrypt_generic_init($td, $key, $iv) !== 0 )
						return false;

					$string = mcrypt_generic($td, $string);
					$string = $iv . $string;

					$mac = $this->pbkdf2($string, $key, 1000, 32);

					$string .= $mac;

					mcrypt_generic_deinit($td);
					mcrypt_module_close($td);

					$encrypted = base64_encode($string);

					return $encrypted;

				}

			}

		/**
		*
		* Método encargado de desencriptar una cadena.
		*
		* @param string $string Cadena a desencriptar.
		* @param string $key Semilla con la cual desencriptar.
		* @param string $secLevel Nivel de seguridad de encriptación (1: Normal, 2: Alto).
		*
		* @return string Cadena desencriptada.
		*
		*/

			public function decrypt( $string, $key, $secLevel = 2 )
			{

				if( $secLevel == 1 ){

					$result = '';
					$string = base64_decode($string);

					for( $i=0; $i<strlen($string); $i++ ){
						
						$char       = substr($string, $i, 1);
						$keychar    = substr($key, ($i % strlen($key)) - 1, 1);
						$char       = chr(ord($char) - ord($keychar));
						$result .= $char;
					
					}

					return $result;

				} elseif( $secLevel == 2 ){

					$string = base64_decode($string);

					if ( !$td = mcrypt_module_open($this->_algorithm, '', $this->_mode, '') )
						return false;

					$iv = substr($string, 0, 32);
					$mo = strlen($string) - 32;
					$em = substr($string, $mo);

					$string = substr($string, 32, strlen($string) - 64);
					$mac = $this->pbkdf2($iv . $string, $key, 1000, 32);

					if( $em != $mac )
						return false;

					if( mcrypt_generic_init($td, $key, $iv) !== 0 )
						return false;

					$string = mdecrypt_generic($td, $string);
					$string = unserialize($string);

					mcrypt_generic_deinit($td);
					mcrypt_module_close($td);

					return $string;

				}

			}

		/**
		*
		* Método utilizado por los dos métodos anteriores para dar aleatoriedad.
		*
		* @param string $p Contraseña.
		* @param string $s Semilla.
		* @param int $c Número de iteraciones.
		* @param int $kl Tamaño de la "Key".
		* @param string $a Algoritmo de hash.
		*
		* @return string "Key" aleatoria.
		*
		*/

			public function pbkdf2( $p, $s, $c, $kl, $a = 'sha256' )
			{

				$hl = strlen(hash($a, null, true));
				$kb = ceil($kl / $hl);
				$dk = '';

				for( $block = 1; $block <= $kb; $block++ ){

					$ib = $b = hash_hmac($a, $s . pack('N', $block), $p, true);

					for( $i = 1; $i < $c; $i++ )

						$ib ^= ( $b = hash_hmac($a, $b, $p, true) );

					$dk .= $ib;

				}

				return substr($dk, 0, $kl);

			}

	}

?>