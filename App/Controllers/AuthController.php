<?php

namespace App\Controllers;

use App\DAO\TokensDAO;
use App\DAO\UsuariosDAO;
use App\Models\TokenModel;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use Firebase\JWT\JWT;

final class AuthController
{
    public function login(Request $request, Response $response, array $args): Response
    {
        $data = $request->getParsedBody();

        $email = $data['email'];
        $senha = $data['senha'];

        $usuarioDAO = new UsuariosDAO();
        $usuario = $usuarioDAO->getUserByEmail($email);

        if (is_null($usuario)) {
            return $response->withStatus(401);
        }

        if (!password_verify($senha, $usuario->getSenha())) {
            return $response->withStatus(401);
        }

        $expiredDate = (new \DateTime('now', new \DateTimeZone('America/Sao_Paulo')))
            ->modify('+2 days')->format('Y-m-d H:i:s');

        $tokenPayLoad = [
            'sub' => $usuario->getId(),
            'name' => $usuario->getNome(),
            'email' => $usuario->getEmail(),
            'expired_at' => $expiredDate
        ];

        $token = JWT::encode($tokenPayLoad, getenv('JWT_SECRET_KEY'));

        $refreshTokenPayload = [
            "email" => $usuario->getEmail(),
            'random' => uniqid()
        ];

        $refreshToken = JWT::encode($refreshTokenPayload, getenv('JWT_SECRET_KEY'));

        $tokenModel = new TokenModel;
        $tokenModel->setExpired_at($expiredDate)
            ->setRefresh_token($refreshToken)
            ->setToken($token)
            ->setUsuario_id($usuario->getId());

        $tokensDAO = new TokensDAO();
        $tokensDAO->createToken($tokenModel);

        $response = $response->withJson([
            "token" => $token,
            "refresh_token" => $refreshToken
        ]);

        return $response;
    }

    public function refreshToken(Request $request, Response $response, array $args): Response
    {
        $data = $request->getParsedBody();
        $refreshToken = $data['refresh_token'];

        $refreshTokenDecoded = JWT::decode(
            $refreshToken,
            getenv('JWT_SECRET_KEY'),
            ['HS256']
        );

        $tokenDAO = new TokensDAO();
        $refreshTokenExists = $tokenDAO->verifyRefreshToken($refreshToken);
        if (!$refreshTokenExists) {
            return $response->withStatus(401);
        }

        $usuariosDAO = new UsuariosDAO();
        $usuario = $usuariosDAO->getUserByEmail($refreshTokenDecoded->email);
        if (is_null($usuario)) {
            return $response->withStatus(401);
        }

        $expiredDate = (new \DateTime('now', new \DateTimeZone('America/Sao_Paulo')))
            ->modify('+2 days')->format('Y-m-d H:i:s');

        $tokenPayLoad = [
            'sub' => $usuario->getId(),
            'name' => $usuario->getNome(),
            'email' => $usuario->getEmail(),
            'expired_at' => $expiredDate
        ];

        $token = JWT::encode($tokenPayLoad, getenv('JWT_SECRET_KEY'));

        $refreshTokenPayload = [
            "email" => $usuario->getEmail(),
            'random' => uniqid()
        ];

        $refreshToken = JWT::encode($refreshTokenPayload, getenv('JWT_SECRET_KEY'));

        $tokenModel = new TokenModel;
        $tokenModel->setExpired_at($expiredDate)
            ->setRefresh_token($refreshToken)
            ->setToken($token)
            ->setUsuario_id($usuario->getId());

        $tokensDAO = new TokensDAO();
        $tokensDAO->createToken($tokenModel);

        $response = $response->withJson([
            "token" => $token,
            "refresh_token" => $refreshToken
        ]);

        return $response;
    }
}
