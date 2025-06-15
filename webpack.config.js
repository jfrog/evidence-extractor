import webpack from 'webpack';
import NodePolyfillPlugin from 'node-polyfill-webpack-plugin';

import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default {
    mode: 'development',    
    entry: './src/dsse.js',
    output: {
        filename: 'bundle.js',
        path: path.resolve(__dirname, 'dist'),
    },
    module: {
        rules: [
            {
                test: /\.m?js/,
                resolve: {
                    fullySpecified: false
                }
            }
        ]
    },
    resolve: {
        fallback: {
            "buffer": require.resolve("buffer/"),
            "fs": false,
            "path": false,
            "crypto": false,
        }
    },
    plugins: [
        new NodePolyfillPlugin(),
        new webpack.ProvidePlugin({
            Buffer: ['buffer', 'Buffer'],
            process: 'process/browser'
        }),
        new webpack.NormalModuleReplacementPlugin(/^node:/, (resource) => {
            const mod = resource.request.replace(/^node:/, '');
            resource.request = mod;
        })
    ]
}; 