phalcon-recaptcha
=================

This is a minimalist wrapper with which you can easily integrate [reCAPTCHA](http://www.google.com/recaptcha) into your application based on [Phalcon Framework](http://phalconphp.com).

### Quickstart ###

1. Get the Recaptcha.php class and put it wherever you want. For example it can be ```/app/lib``` folder of your application.
2. Connect this class to your application. Write up a path to directory (or namespace) where this class is located.

#### How to show reCAPTCHA form ####

Call **get** method of **Recaptcha** class. This method is static, so you can call it without class instantiation, like this: ```php Recaptcha::get($yourPublicKey) ```

#### How to check captcha ####

By the same way as above. You can just call **check** method with a set of parameters, like this:
```php
$answer = Recaptcha::check(
    $yourPrivateKey,
    $_SERVER['REMOTE_ADDR'],
    $this->request->getPost('recaptcha_challenge_field'),
    $this->request->getPost('recaptcha_response_field')
);
if ($answer) {
  // Captcha is correct
} else {
  // Captcha is incorrect
}
```

#### Le voilà! ####

Star me if I helped you a little :)
