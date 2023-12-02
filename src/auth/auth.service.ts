import {
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import * as bcrypt from 'bcrypt';
import { AuthDto } from './dto';
import { Tokens } from './types';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
  constructor(
    private prismaService: PrismaService,
    private jwtService: JwtService,
  ) {}

  public async localSignUp(authDto: AuthDto): Promise<Tokens> {
    try {
      const hash = await this.hashData(10, authDto.password);
      const newUser = await this.prismaService.user.create({
        data: {
          email: authDto.email,
          password: hash,
        },
      });

      const tokens = await this.getTokens(newUser.id, newUser.email);
      await this.updateHashRt(newUser.id, tokens.refresh_token);
      return tokens;
    } catch (error) {
      throw new HttpException(
        error?.message ?? 'Something went wrong',
        error?.status ?? HttpStatus.BAD_REQUEST,
      );
    }
  }

  public async localSignIn(authDto: AuthDto): Promise<Tokens> {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          email: authDto.email,
        },
      });
      if (!user) {
        throw new ForbiddenException('Access denied');
      }
      const isPasswordMatch = await bcrypt.compare(
        authDto.password,
        user.password,
      );
      if (!isPasswordMatch) {
        throw new ForbiddenException('Access denied');
      }
      const tokens = await this.getTokens(user.id, user.email);
      await this.updateHashRt(user.id, tokens.refresh_token);
      return tokens;
    } catch (error) {
      throw new HttpException(
        error?.message ?? 'Something went wrong',
        error?.status ?? HttpStatus.BAD_REQUEST,
      );
    }
  }

  public async logout(id: number) {
    try {
      await this.prismaService.user.updateMany({
        where: {
          id,
          hashRefreshToken: {
            not: null,
          },
        },
        data: {
          hashRefreshToken: null,
        },
      });
    } catch (error) {
      throw new HttpException(
        error?.message ?? 'Something went wrong',
        error?.status ?? HttpStatus.BAD_REQUEST,
      );
    }
  }

  public async refreshTokens(id: number, rt: string): Promise<Tokens> {
    try {
      const user = await this.prismaService.user.findUnique({
        where: {
          id,
        },
      });
      if (!user || !user.hashRefreshToken)
        throw new ForbiddenException('Access denied');
      const isRtMatch = await bcrypt.compare(rt, user?.hashRefreshToken);
      if (!isRtMatch) throw new ForbiddenException('Access denied');
      const tokens = await this.getTokens(user.id, user.email);
      await this.updateHashRt(user.id, tokens.refresh_token);
      return tokens;
    } catch (error) {
      throw new HttpException(
        error?.message ?? 'Something went wrong',
        error?.status ?? HttpStatus.BAD_REQUEST,
      );
    }
  }

  private async hashData(saltRound: number, data: string) {
    const salt = await bcrypt.genSalt(saltRound);
    return await bcrypt.hash(data, salt);
  }

  private async getTokens(userId: number, email: string): Promise<Tokens> {
    const accessToken = this.jwtService.signAsync(
      {
        sub: userId,
        email,
      },
      { expiresIn: 60 * 15, secret: 'at-secret' },
    );
    const refreshToken = this.jwtService.signAsync(
      {
        sub: userId,
        email,
      },
      { expiresIn: 60 * 60 * 24 * 7, secret: 'rt-secret' },
    );

    const [at, rt] = await Promise.all([accessToken, refreshToken]);
    return {
      access_token: at,
      refresh_token: rt,
    };
  }

  private async updateHashRt(id: number, rt: string) {
    const hashRefreshToken = await this.hashData(10, rt);
    await this.prismaService.user.update({
      where: {
        id,
      },
      data: {
        hashRefreshToken,
      },
    });
  }
}
