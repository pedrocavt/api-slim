<?php

namespace App\Controllers;

use App\DAO\LojasDAO;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Message\ResponseInterface as Response;
use App\Models\LojaModel;

final class LojaController
{
    public function getLojas(Request $request, Response $response, array $args): Response
    {
        $lojasDAO = new LojasDAO();

        $lojas = $lojasDAO->getAllLojas();
        $response = $response->withJson($lojas);

        return $response;
    }

    public function insertLoja(Request $request, Response $response, array $args): Response
    {
        $data = $request->getParsedBody();

        $lojasDAO = new LojasDAO;
        $loja = new LojaModel();
        $loja->setNome($data['nome']);
        $loja->setEndereco($data['endereco']);
        $loja->setTelefone($data['telefone']);
        $lojasDAO->insertLojas($loja);

        $response = $response->withJson([
            'message' => 'Loja inserida com sucesso'
        ]);
        return $response;
    }

    public function updateLoja(Request $request, Response $response, array $args): Response
    {
        $data = $request->getParsedBody();

        $lojasDAO = new LojasDAO();
        $loja = new LojaModel();
        $loja->setId((int)$data['id'])
            ->setNome($data['nome'])
            ->setEndereco($data['endereco'])
            ->setTelefone($data['telefone']);
        $lojasDAO->updateLoja($loja);

        $response = $response->withJson([
            'message' => 'Loja atualizada com sucesso'
        ]);

        return $response;
    }

    public function deleteLoja(Request $request, Response $response, array $args): Response
    {
        $queryParams = $request->getQueryParams();

        $lojasDAO = new LojasDAO();
        $id = (int)$queryParams['id'];
        $lojasDAO->deleteLoja($id);

        $response = $response->withJson([
            'message' => 'Loja excluída com sucesso!'
        ]);

        return $response;
    }
}
