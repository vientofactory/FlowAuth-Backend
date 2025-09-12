import { IsNotEmpty, IsString, IsArray, IsOptional } from 'class-validator';

export class CreateClientDto {
  @IsString()
  @IsNotEmpty()
  name: string;

  @IsString()
  @IsOptional()
  description?: string;

  @IsArray()
  @IsString({ each: true })
  redirectUris: string[];

  @IsArray()
  @IsString({ each: true })
  grants: string[];
}
