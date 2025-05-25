import { NativeModules, Platform } from 'react-native';
import { KanonModule } from './kanon/KanonModule';
import "reflect-metadata";
const LINKING_ERROR =
  `The package 'react-native-credo-sql' doesn't seem to be linked. Make sure: \n\n` +
  Platform.select({ ios: "- You have run 'pod install'\n", default: '' }) +
  '- You rebuilt the app after installing the package\n' +
  '- You are not using Expo Go\n';

const Kanon = NativeModules.Kanon
  ? NativeModules.Kanon
  : new Proxy(
      {},
      {
        get() {
          throw new Error(LINKING_ERROR);
        },
      }
    );

export function multiply(a: number, b: number): Promise<number> {
  return Kanon.multiply(a, b);
}

export { KanonModule };
