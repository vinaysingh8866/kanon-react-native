module.exports = {
  presets: ['react-native-builder-bob/babel-preset'],
  plugins: [
    ['@babel/plugin-proposal-decorators', { legacy: true }],
    'babel-plugin-transform-typescript-metadata',
  ],
};
