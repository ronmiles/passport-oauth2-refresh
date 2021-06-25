import OAuth2Strategy from "passport-oauth2";
import { OAuth2 } from 'oauth';

class UnprotectedOAuth2 extends OAuth2 {
    
}

class UnprotectedOAuth2Strategy extends OAuth2Strategy {
    _oauth2: OAuth2;
    
}

type Unprotect<T> {
   -readonly [Property in keyof T]: T[Property];
}