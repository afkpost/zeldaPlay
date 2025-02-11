import { Args, Mutation, Query, Resolver } from '@nestjs/graphql';
import { Observable } from 'rxjs';
import { AuthService } from './auth.service';
import { AuthDTO, LoginDTO, ofAuth, returnAuth, SignupDTO } from './models';

@Resolver(ofAuth)
export class AuthResolver {
  constructor(private readonly authService: AuthService) {}

  @Query(returnAuth, { name: 'login' })
  login(@Args() loginBody: LoginDTO): Observable<AuthDTO> {
    return this.authService.login(loginBody);
  }

  @Mutation(returnAuth, { name: 'signup' })
  signup(@Args('signupBody') signupBody: SignupDTO): Observable<AuthDTO> {
    return this.authService.signup(signupBody);
  }
}
