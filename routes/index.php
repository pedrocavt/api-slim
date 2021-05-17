<?php

use function src\{
    basicAuth,
    jwtAuth,
    slimConfiguration,
};

use App\Controllers\{
    AuthController,
    ProdutoController,
    LojaController
};
use App\Middlewares\JwtDateTimeMiddleware;
use Tuupola\Middleware\JwtAuthentication;

$app = new \Slim\App(slimConfiguration());

$app->post("/login", AuthController::class . ':login');
$app->post('/refresh-token', AuthController::class . ':refreshToken');

$app->get('/teste', function () {
    echo "oi";
})->add(new JwtDateTimeMiddleware())->add(jwtAuth());

$app->group('', function () use ($app) {
    $app->get('/loja', LojaController::class . ':getLojas');
    $app->post('/loja', LojaController::class . ':insertLoja');
    $app->put('/loja', LojaController::class . ':updateLoja');
    $app->delete('/loja', LojaController::class . ':deleteLoja');

    $app->get('/produtos', ProdutoController::class . ':getProdutos');
    $app->post('/produtos', ProdutoController::class . ':insertProduto');
    $app->put('/produtos', ProdutoController::class . ':updateProduto');
    $app->delete('/produtos', ProdutoController::class . ':deleteProduto');
})->add(basicAuth());

$app->run();
