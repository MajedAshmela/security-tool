<?php

use App\Http\Controllers\Api\HashIdentifierController;
use Illuminate\Support\Facades\Route;

Route::post('/identify', [HashIdentifierController::class, 'identify'])
    ->middleware('throttle:30,1')
    ->name('api.hashes.identify');
