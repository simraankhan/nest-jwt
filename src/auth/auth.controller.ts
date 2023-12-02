import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { RtGuard } from 'src/common/guard';
import { GetUser, Public } from 'src/common/decorator';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Public()
  @Post('/local/sign-up')
  public localSignUp(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.localSignUp(authDto);
  }

  @Public()
  @Post('/local/sign-in')
  @HttpCode(HttpStatus.OK)
  public async localSignIn(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.localSignIn(authDto);
  }

  @Post('/logout')
  @HttpCode(HttpStatus.OK)
  public async logout(@GetUser('userId') userId: number) {
    return this.authService.logout(userId);
  }

  @Public()
  @UseGuards(RtGuard)
  @Post('/refresh-token')
  @HttpCode(HttpStatus.OK)
  public async refreshTokens(@GetUser() user: any): Promise<Tokens> {
    return this.authService.refreshTokens(user.userId, user.refreshToken);
  }
}
