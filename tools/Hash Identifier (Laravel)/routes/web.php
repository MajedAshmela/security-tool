<?php

use App\Http\Controllers\HashIdentifierController;
use Illuminate\Support\Facades\Route;

Route::get('/', [HashIdentifierController::class, 'index'])->name('hashes.index');
Route::post('/identify', [HashIdentifierController::class, 'identify'])->name('hashes.identify');
