import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Length } from 'class-validator';

export class CreateUserDto {
  @ApiProperty({ example: 'user@mail.com', description: 'User email' })
  @IsString()
  @IsEmail()
  readonly email: string;
  @ApiProperty({ example: 'qwerty', description: 'User password' })
  @IsString()
  @Length(4, 16, { message: 'more than 3 and less than 17' })
  readonly password: string;
}
