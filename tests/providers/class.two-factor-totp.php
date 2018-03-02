<?php
/**
 * Test Two Factor Email.
 */

class Tests_Two_Factor_Totp extends WP_UnitTestCase {

	private static $token = '12345678901234567890';
	private static $step = 30;

	private static $vectors = [
		59          => ['94287082', '46119246', '90693936'],
		1111111109  => ['07081804', '68084774', '25091201'],
		1111111111  => ['14050471', '67062674', '99943326'],
		1234567890  => ['89005924', '91819424', '93441116'],
		2000000000  => ['69279037', '90698825', '38618901'],
		20000000000 => ['65353130', '77737706', '47863826']
	];

	/**
	 * @var Two_Factor_Totp
	 */
	protected $provider;

	/**
	 * Set up a test case.
	 *
	 * @see WP_UnitTestCase::setup()
	 */
	public function setUp() {
		parent::setUp();

		$this->provider = Two_Factor_Totp::get_instance();
	}

	public function tearDown() {
		unset( $this->provider );

		parent::tearDown();
	}

	/**
	 * @covers Two_Factor_Totp::get_instance
	 */
	public function test_get_instance() {
		$this->assertNotNull( $this->provider->get_instance() );
	}

	/**
	 * @covers Two_Factor_Totp::get_label
	 */
	public function test_get_label() {
		$this->assertContains( 'Google Authenticator', $this->provider->get_label() );
	}

	/**
	 * @covers Two_Factor_Totp::user_two_factor_options
	 */
	public function test_user_two_factor_options_empty() {
		$this->assertFalse( $this->provider->user_two_factor_options( get_current_user() ) );
	}

	/**
	 * @covers Two_Factor_Totp::user_two_factor_options
	 * @covers Two_Factor_Totp::is_available_for_user
	 */
	public function test_user_two_factor_options_generates_key() {
		$user = new WP_User( $this->factory->user->create() );

		ob_start();
		$this->provider->user_two_factor_options( $user );
		$content = ob_get_clean();

		$this->assertContains( __( 'Authentication Code:', 'two-factor' ), $content );
	}

	/**
	 * @covers Two_Factor_Totp::user_two_factor_options_update
	 * @covers Two_Factor_Totp::is_available_for_user
	 */
	public function test_user_two_factor_options_update_no_key() {
		$user = new WP_User( $this->factory->user->create() );

		$request_key = '_nonce_user_two_factor_totp_options';
		$_POST[$request_key] = wp_create_nonce( 'user_two_factor_totp_options' );
		$_REQUEST[$request_key] = $_POST[$request_key];

		ob_start();
		$this->assertFalse( $this->provider->user_two_factor_options_update( $user->ID ) );
		$content = ob_get_clean();

		unset( $_REQUEST[$request_key] );
		unset( $_POST[$request_key] );

		$this->assertFalse( $this->provider->is_available_for_user( $user ) );
	}

	/**
	 * @covers Two_Factor_Totp::user_two_factor_options_update
	 * @covers Two_Factor_Totp::is_available_for_user
	 */
	public function test_user_two_factor_options_update_set_key_no_authcode() {
		$user = new WP_User( $this->factory->user->create() );

		$request_key = '_nonce_user_two_factor_totp_options';
		$_POST[$request_key] = wp_create_nonce( 'user_two_factor_totp_options' );
		$_REQUEST[$request_key] = $_POST[$request_key];

		$_POST['two-factor-totp-key'] = $this->provider->generate_key();

		ob_start();
		$this->provider->user_two_factor_options_update( $user->ID );
		$content = ob_get_clean();

		unset( $_POST['two-factor-totp-key'] );

		unset( $_REQUEST[$request_key] );
		unset( $_POST[$request_key] );

		$this->assertFalse( $this->provider->is_available_for_user( $user ) );
	}

	/**
	 * @covers Two_Factor_Totp::user_two_factor_options_update
	 * @covers Two_Factor_Totp::is_available_for_user
	 */
	public function test_user_two_factor_options_update_set_key_bad_auth_code() {
		$user = new WP_User( $this->factory->user->create() );

		$request_key = '_nonce_user_two_factor_totp_options';
		$_POST[$request_key] = wp_create_nonce( 'user_two_factor_totp_options' );
		$_REQUEST[$request_key] = $_POST[$request_key];

		$_POST['two-factor-totp-key'] = $this->provider->generate_key();
		$_POST['two-factor-totp-authcode'] = 'bad_test_authcode';

		ob_start();
		$this->provider->user_two_factor_options_update( $user->ID );
		$content = ob_get_clean();

		unset( $_POST['two-factor-totp-authcode'] );
		unset( $_POST['two-factor-totp-key'] );

		unset( $_REQUEST[$request_key] );
		unset( $_POST[$request_key] );

		$this->assertFalse( $this->provider->is_available_for_user( $user ) );
	}

	/**
	 * @covers Two_Factor_Totp::user_two_factor_options_update
	 * @covers Two_Factor_Totp::is_available_for_user
	 */
	public function test_user_two_factor_options_update_set_key() {
		$user = new WP_User( $this->factory->user->create() );

		$request_key = '_nonce_user_two_factor_totp_options';
		$_POST[$request_key] = wp_create_nonce( 'user_two_factor_totp_options' );
		$_REQUEST[$request_key] = $_POST[$request_key];

		$key = $this->provider->generate_key();
		$_POST['two-factor-totp-key'] = $key;
		$_POST['two-factor-totp-authcode'] = $this->provider->calc_totp( $key );

		ob_start();
		$this->provider->user_two_factor_options_update( $user->ID );
		$content = ob_get_clean();

		unset( $_POST['two-factor-totp-authcode'] );
		unset( $_POST['two-factor-totp-key'] );

		unset( $_REQUEST[$request_key] );
		unset( $_POST[$request_key] );

		$this->assertTrue( $this->provider->is_available_for_user( $user ) );
	}

	/**
	 * @covers Two_Factor_Totp::base32_encode
	 */
	public function test_base32_encode() {
		$string = 'EV5XW7TOL4QHIKBIGVEU23KAFRND66LY';
		$string_base32 = 'IVLDKWCXG5KE6TBUKFEESS2CJFDVMRKVGIZUWQKGKJHEINRWJRMQ';

		$this->assertEquals( $string_base32, $this->provider->base32_encode( $string ) );
	}

	/**
	 * @covers Two_Factor_Totp::base32_encode
	 */
	public function test_base32_decode() {
		$string = 'EV5XW7TOL4QHIKBIGVEU23KAFRND66LY';
		$string_base32 = 'IVLDKWCXG5KE6TBUKFEESS2CJFDVMRKVGIZUWQKGKJHEINRWJRMQ';

		$this->assertEquals( $string, $this->provider->base32_decode( $string_base32 ) );
	}

	/**
	 * @covers Two_Factor_Totp::is_valid_authcode
	 * @covers Two_Factor_Totp::generate_key
	 * @covers Two_Factor_Totp::calc_totp
	 */
	public function test_is_valid_authcode() {
		$key = $this->provider->generate_key();
		$authcode = $this->provider->calc_totp( $key );

		$this->assertTrue( $this->provider->is_valid_authcode( $key, $authcode ) );
	}

	/**
	 * @covers Two_Factor_Totp::calc_totp
	 */
	public function test_sha1_generate() {
		if ( PHP_INT_SIZE === 4 ) {
			$this->markTestSkipped( 'calc_totp requires 64-bit PHP' );
		}

		$provider = $this->provider;
		$hash = 'sha1';
		$token = $provider->base32_encode( self::$token );

		foreach (self::$vectors as $time => $vector) {
			$provider::__set_time( (int) $time );
			$this->assertEquals( $vector[0], $provider::calc_totp( $token, false, 8, $hash, self::$step ) );
			$this->assertEquals( substr( $vector[0], 2 ), $provider::calc_totp( $token, false, 6, $hash, self::$step ) );
		}
	}

	/**
	 * @covers Two_Factor_Totp::is_valid_authcode
	 * @covers Two_Factor_Totp::calc_totp
	 */
	public function test_sha1_authenticate() {
		if ( PHP_INT_SIZE === 4 ) {
			$this->markTestSkipped( 'calc_totp requires 64-bit PHP' );
		}

		$provider = $this->provider;
		$hash = 'sha1';
		$token = $provider->base32_encode( self::$token );

		foreach ( self::$vectors as $time => $vector ) {
			$provider::__set_time( (int) $time );
			$this->assertTrue( $provider::is_valid_authcode( $token, $vector[0], $hash ) );
			$this->assertTrue( $provider::is_valid_authcode( $token, substr( $vector[0], 2 ), $hash ) );
		}
	}

	/**
	 * @covers Two_Factor_Totp::calc_totp
	 */
	public function test_sha256_generate() {
		if (PHP_INT_SIZE === 4) {
			$this->markTestSkipped( 'calc_totp requires 64-bit PHP' );
		}

		$provider = $this->provider;
		$hash = 'sha256';
		$token = $provider->base32_encode( self::$token );

		foreach ( self::$vectors as $time => $vector ) {
			$provider::__set_time( (int) $time );
			$this->assertEquals( $vector[1], $provider::calc_totp( $token, false, 8, $hash, self::$step ) );
			$this->assertEquals( substr( $vector[1], 2 ), $provider::calc_totp( $token, false, 6, $hash, self::$step ) );
		}
	}

	/**
	 * @covers Two_Factor_Totp::is_valid_authcode
	 * @covers Two_Factor_Totp::calc_totp
	 */
	public function test_sha256_authenticate() {
		if ( PHP_INT_SIZE === 4 ) {
			$this->markTestSkipped( 'calc_totp requires 64-bit PHP' );
		}

		$provider = $this->provider;
		$hash = 'sha256';
		$token = $provider->base32_encode( self::$token );

		foreach ( self::$vectors as $time => $vector ) {
			$provider::__set_time( (int) $time );
			$this->assertTrue( $provider::is_valid_authcode( $token, $vector[1], $hash ) );
			$this->assertTrue( $provider::is_valid_authcode( $token, substr( $vector[1], 2 ), $hash ) );
		}
	}

	/**
	 * @covers Two_Factor_Totp::calc_totp
	 */
	public function test_sha512_generate() {
		if ( PHP_INT_SIZE === 4 ) {
			$this->markTestSkipped('calc_totp requires 64-bit PHP');
		}

		$provider = $this->provider;
		$hash = 'sha512';
		$token = $provider->base32_encode( self::$token );

		foreach ( self::$vectors as $time => $vector ) {
			$provider::__set_time( (int) $time );
			$this->assertEquals( $vector[2], $provider::calc_totp( $token, false, 8, $hash, self::$step ) );
			$this->assertEquals( substr($vector[2], 2 ), $provider::calc_totp( $token, false, 6, $hash, self::$step ) );
		}
	}

	/**
	 * @covers Two_Factor_Totp::is_valid_authcode
	 * @covers Two_Factor_Totp::calc_totp
	 */
	public function test_sha512_authenticate() {
		if ( PHP_INT_SIZE === 4 ) {
			$this->markTestSkipped( 'calc_totp requires 64-bit PHP' );
		}

		$provider = $this->provider;
		$hash = 'sha512';
		$token = $provider->base32_encode( self::$token );

		foreach ( self::$vectors as $time => $vector ) {
			$provider::__set_time( (int) $time );
			$this->assertTrue( $provider::is_valid_authcode( $token, $vector[2], $hash ) );
			$this->assertTrue( $provider::is_valid_authcode( $token, substr( $vector[2], 2 ), $hash ) );
		}

	}
}
