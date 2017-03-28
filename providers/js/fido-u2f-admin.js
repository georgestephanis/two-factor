/* global u2f, u2fL10n */
( function( $ ) {
	var $button = $( '#register_security_key' );
	var $status_notice = $( '#security-keys-section .security-key-status' )
	var u2f_supported = false;

	$status_notice.text( u2fL10n.text.u2f_not_supported );

	u2f.getApiVersion( function() {
		u2f_supported = true;

		$status_notice.text( '' );
	} );

	$button.click( function() {
		var registerRequest;

		if ( $( this ).prop( 'disabled' ) ) {
			return false;
		}

		window.console.log( 'sign', u2fL10n.register.request );

		$( this ).prop( 'disabled', true );
		$( '.register-security-key .spinner' ).addClass( 'is-active' );

		registerRequest = {
			version: u2fL10n.register.request.version,
			challenge: u2fL10n.register.request.challenge
		};

		u2f.register( u2fL10n.register.request.appId, [ registerRequest ], u2fL10n.register.sigs, function( data ) {
			$( '.register-security-key .spinner' ).removeClass( 'is-active' );
			$button.prop( 'disabled', false );

			if ( data.errorCode ) {
				window.console.log( 'Registration Failed', data.errorCode );

				if ( u2fL10n.text.error_codes[ data.errorCode ] ) {
					$status_notice.text( u2fL10n.text.error_codes[ data.errorCode ] );
				} else {
					$status_notice.text( u2fL10n.text.error_codes[ u2fL10n.text.error ] );
				}

				return false;
			}

			$( '#do_new_security_key' ).val( 'true' );
			$( '#u2f_response' ).val( JSON.stringify( data ) );

			// See: http://stackoverflow.com/questions/833032/submit-is-not-a-function-error-in-javascript
			$( '<form>' )[0].submit.call( $( '#your-profile' )[0] );
		} );
	} );
} )( jQuery );
